#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

import praw
import requests
from praw.exceptions import RedditAPIException
from praw.models import Comment, Message, Submission
from prawcore.exceptions import OAuthException, PrawcoreException

from . import __version__


class CliError(RuntimeError):
    pass


@dataclass
class RedditConfig:
    client_id: str
    client_secret: str
    user_agent: str
    refresh_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


def _getenv(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _truthy(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def default_user_agent() -> str:
    return _getenv("REDDIT_USER_AGENT") or "mac:openclaw-reddit-cli:v0.1 (by /u/unknown)"


def oauth_core_present() -> bool:
    return bool(_getenv("REDDIT_CLIENT_ID") and _getenv("REDDIT_CLIENT_SECRET"))


def prefer_public_mode() -> bool:
    if _truthy(_getenv("REDDIT_PUBLIC_ONLY")):
        return True
    return not oauth_core_present()


def load_config(require_user_auth: bool = False) -> RedditConfig:
    client_id = _getenv("REDDIT_CLIENT_ID")
    client_secret = _getenv("REDDIT_CLIENT_SECRET")
    user_agent = default_user_agent()
    refresh_token = _getenv("REDDIT_REFRESH_TOKEN")
    username = _getenv("REDDIT_USERNAME")
    password = _getenv("REDDIT_PASSWORD")

    missing = []
    if not client_id:
        missing.append("REDDIT_CLIENT_ID")
    if not client_secret:
        missing.append("REDDIT_CLIENT_SECRET")

    if missing:
        raise CliError(f"Missing required env vars: {', '.join(missing)}")

    if require_user_auth and not (refresh_token or (username and password)):
        raise CliError(
            "Missing user auth. Set REDDIT_REFRESH_TOKEN (preferred) "
            "or REDDIT_USERNAME and REDDIT_PASSWORD."
        )

    return RedditConfig(
        client_id=client_id,
        client_secret=client_secret,
        user_agent=user_agent,
        refresh_token=refresh_token,
        username=username,
        password=password,
    )


def build_reddit(config: RedditConfig, require_user_auth: bool = False) -> praw.Reddit:
    kwargs: dict[str, Any] = {
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "user_agent": config.user_agent,
        "ratelimit_seconds": 5,
    }

    if config.refresh_token:
        kwargs["refresh_token"] = config.refresh_token
    elif config.username and config.password:
        kwargs["username"] = config.username
        kwargs["password"] = config.password

    reddit = praw.Reddit(**kwargs)

    if require_user_auth:
        me = reddit.user.me()
        if me is None:
            raise CliError("Auth check failed: authenticated user context is unavailable.")

    return reddit


def iso_utc(epoch_seconds: Optional[float]) -> Optional[str]:
    if epoch_seconds is None:
        return None
    try:
        return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def _absolute_permalink(permalink: Optional[str]) -> Optional[str]:
    if not permalink:
        return None
    if permalink.startswith("http://") or permalink.startswith("https://"):
        return permalink
    return f"https://reddit.com{permalink}"


def serialize_submission(sub: Submission) -> dict[str, Any]:
    return {
        "kind": "submission",
        "id": sub.id,
        "name": sub.name,
        "title": sub.title,
        "selftext": sub.selftext,
        "url": sub.url,
        "permalink": f"https://reddit.com{sub.permalink}",
        "subreddit": str(sub.subreddit),
        "author": None if sub.author is None else str(sub.author),
        "score": sub.score,
        "upvote_ratio": getattr(sub, "upvote_ratio", None),
        "num_comments": sub.num_comments,
        "created_utc": iso_utc(sub.created_utc),
        "over_18": sub.over_18,
        "is_self": sub.is_self,
        "saved": getattr(sub, "saved", None),
    }


def serialize_submission_data(data: dict[str, Any]) -> dict[str, Any]:
    link_id = data.get("id")
    return {
        "kind": "submission",
        "id": link_id,
        "name": data.get("name") or (f"t3_{link_id}" if link_id else None),
        "title": data.get("title"),
        "selftext": data.get("selftext"),
        "url": data.get("url"),
        "permalink": _absolute_permalink(data.get("permalink")),
        "subreddit": data.get("subreddit"),
        "author": data.get("author"),
        "score": data.get("score"),
        "upvote_ratio": data.get("upvote_ratio"),
        "num_comments": data.get("num_comments"),
        "created_utc": iso_utc(data.get("created_utc")),
        "over_18": data.get("over_18"),
        "is_self": data.get("is_self"),
        "saved": data.get("saved"),
    }


def serialize_comment(comment: Comment) -> dict[str, Any]:
    return {
        "kind": "comment",
        "id": comment.id,
        "name": comment.name,
        "body": comment.body,
        "permalink": f"https://reddit.com{comment.permalink}",
        "subreddit": str(comment.subreddit),
        "author": None if comment.author is None else str(comment.author),
        "score": comment.score,
        "created_utc": iso_utc(comment.created_utc),
        "submission_id": comment.submission.id,
        "saved": getattr(comment, "saved", None),
    }


def serialize_comment_data(data: dict[str, Any]) -> dict[str, Any]:
    link_id = data.get("link_id")
    submission_id = None
    if isinstance(link_id, str):
        submission_id = link_id.replace("t3_", "")

    return {
        "kind": "comment",
        "id": data.get("id"),
        "name": data.get("name") or (f"t1_{data.get('id')}" if data.get("id") else None),
        "body": data.get("body"),
        "permalink": _absolute_permalink(data.get("permalink")),
        "subreddit": data.get("subreddit"),
        "author": data.get("author"),
        "score": data.get("score"),
        "created_utc": iso_utc(data.get("created_utc")),
        "submission_id": submission_id,
        "saved": data.get("saved"),
    }


def serialize_message(msg: Message) -> dict[str, Any]:
    return {
        "kind": "message",
        "id": msg.id,
        "name": msg.name,
        "subject": msg.subject,
        "body": msg.body,
        "author": None if msg.author is None else str(msg.author),
        "dest": getattr(msg, "dest", None),
        "created_utc": iso_utc(msg.created_utc),
        "was_comment": msg.was_comment,
        "subreddit": None if msg.subreddit is None else str(msg.subreddit),
    }


def serialize_item(item: Any) -> dict[str, Any]:
    if isinstance(item, Submission):
        return serialize_submission(item)
    if isinstance(item, Comment):
        return serialize_comment(item)
    if isinstance(item, Message):
        return serialize_message(item)
    return {"kind": type(item).__name__, "repr": repr(item)}


def emit(result: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    if isinstance(result, (dict, list)):
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    print(str(result))


def parse_reddit_ref(ref: str) -> tuple[Optional[str], str]:
    ref = ref.strip()
    if ref.startswith("t1_"):
        return "comment", ref[3:]
    if ref.startswith("t3_"):
        return "submission", ref[3:]

    parsed = urlparse(ref)
    if parsed.scheme and parsed.netloc:
        parts = [p for p in parsed.path.split("/") if p]
        if "comments" in parts:
            idx = parts.index("comments")
            submission_id = parts[idx + 1] if len(parts) > idx + 1 else ""
            comment_id = parts[idx + 3] if len(parts) > idx + 3 else ""
            if comment_id:
                return "comment", comment_id
            if submission_id:
                return "submission", submission_id

    return None, ref


def public_get_json(path_or_url: str, params: Optional[dict[str, Any]] = None) -> Any:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        url = path_or_url
    else:
        url = f"https://www.reddit.com{path_or_url}"

    headers = {
        "User-Agent": default_user_agent(),
        "Accept": "application/json",
    }
    merged_params: dict[str, Any] = {"raw_json": 1}
    if params:
        merged_params.update(params)

    resp = requests.get(url, params=merged_params, headers=headers, timeout=20)

    if resp.status_code == 429:
        raise CliError("Rate limited by Reddit public endpoint (429). Try again later.")
    if resp.status_code == 403:
        raise CliError(
            "Forbidden by Reddit public endpoint (403). "
            "Try a different User-Agent or switch to OAuth mode."
        )
    if resp.status_code >= 400:
        body = resp.text[:200].replace("\n", " ")
        raise CliError(f"Public endpoint error {resp.status_code}: {body}")

    return resp.json()


def listing_children(listing: dict[str, Any]) -> list[dict[str, Any]]:
    children = listing.get("data", {}).get("children", [])
    out: list[dict[str, Any]] = []
    for child in children:
        data = child.get("data")
        if isinstance(data, dict):
            out.append(data)
    return out


def load_submission(reddit: praw.Reddit, ref: str) -> Submission:
    kind, value = parse_reddit_ref(ref)
    if kind == "comment":
        raise CliError("Expected submission reference, got comment reference.")

    if ref.startswith("http://") or ref.startswith("https://"):
        sub = reddit.submission(url=ref)
    else:
        sub_id = value[3:] if value.startswith("t3_") else value
        sub = reddit.submission(id=sub_id)

    _ = sub.id
    return sub


def load_comment(reddit: praw.Reddit, ref: str) -> Comment:
    kind, value = parse_reddit_ref(ref)
    if kind == "submission":
        raise CliError("Expected comment reference, got submission reference.")

    comment_id = value[3:] if value.startswith("t1_") else value
    comment = reddit.comment(id=comment_id)
    _ = comment.id
    return comment


def load_thing(reddit: praw.Reddit, ref: str) -> Submission | Comment:
    kind, _ = parse_reddit_ref(ref)

    if kind == "submission":
        return load_submission(reddit, ref)
    if kind == "comment":
        return load_comment(reddit, ref)

    # Ambiguous ID/reference: try submission first, then comment.
    try:
        return load_submission(reddit, ref)
    except Exception:
        pass

    return load_comment(reddit, ref)


def ensure_positive_limit(limit: int) -> int:
    if limit <= 0:
        raise CliError("--limit must be > 0")
    return limit


def require_oauth_for(command_name: str) -> None:
    if prefer_public_mode():
        raise CliError(
            f"{command_name} requires OAuth user auth. "
            "Public read-only mode is enabled (or OAuth credentials are missing)."
        )


def cmd_auth_check(args: argparse.Namespace) -> None:
    if prefer_public_mode():
        listing = public_get_json("/r/python/hot.json", {"limit": 1})
        probe_ok = len(listing_children(listing)) > 0
        out = {
            "ok": probe_ok,
            "mode": "public-read-only",
            "public_read_available": probe_ok,
            "oauth_core_configured": oauth_core_present(),
            "oauth_user_configured": bool(_getenv("REDDIT_REFRESH_TOKEN") or (_getenv("REDDIT_USERNAME") and _getenv("REDDIT_PASSWORD"))),
            "write_actions_available": False,
            "user_agent": default_user_agent(),
        }
        emit(out, args.json)
        return

    cfg = load_config(require_user_auth=False)
    reddit = build_reddit(cfg, require_user_auth=False)

    sample = next(reddit.subreddit("python").hot(limit=1), None)
    if sample is None:
        raise CliError("Auth probe failed: unable to fetch sample subreddit content.")

    out: dict[str, Any] = {
        "ok": True,
        "mode": "oauth",
        "core_credentials": True,
        "user_auth_configured": bool(cfg.refresh_token or (cfg.username and cfg.password)),
        "read_only": reddit.read_only,
        "write_actions_available": True,
    }

    if out["user_auth_configured"]:
        try:
            me = reddit.user.me()
            out["whoami"] = None if me is None else str(me)
            out["user_auth_ok"] = me is not None
        except Exception as exc:
            out["user_auth_ok"] = False
            out["user_auth_error"] = str(exc)

    emit(out, args.json)


def cmd_whoami(args: argparse.Namespace) -> None:
    require_oauth_for("whoami")

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)
    me = reddit.user.me()
    if me is None:
        raise CliError("Not authenticated as a user.")

    out = {
        "name": str(me),
        "id": me.id,
        "comment_karma": me.comment_karma,
        "link_karma": me.link_karma,
        "created_utc": iso_utc(me.created_utc),
        "has_verified_email": getattr(me, "has_verified_email", None),
        "is_gold": getattr(me, "is_gold", None),
        "is_mod": getattr(me, "is_mod", None),
    }
    emit(out, args.json)


def _collect_submissions(items: Iterable[Submission]) -> list[dict[str, Any]]:
    return [serialize_submission(item) for item in items]


def _collect_comments(items: Iterable[Comment]) -> list[dict[str, Any]]:
    return [serialize_comment(item) for item in items]


def cmd_subreddit_read_public(args: argparse.Namespace) -> None:
    limit = ensure_positive_limit(args.limit)

    if args.subreddit_cmd == "posts":
        mode = args.sort
    else:
        mode = args.subreddit_cmd

    path = f"/r/{args.subreddit}/{mode}.json"
    params: dict[str, Any] = {"limit": limit}
    if mode == "top":
        params["t"] = args.time

    listing = public_get_json(path, params)
    items = [serialize_submission_data(item) for item in listing_children(listing)]

    out = {
        "subreddit": args.subreddit,
        "mode": mode,
        "items": items,
    }
    emit(out, args.json)


def cmd_subreddit_read(args: argparse.Namespace) -> None:
    if prefer_public_mode():
        cmd_subreddit_read_public(args)
        return

    cfg = load_config(require_user_auth=False)
    reddit = build_reddit(cfg, require_user_auth=False)
    limit = ensure_positive_limit(args.limit)

    sub = reddit.subreddit(args.subreddit)

    if args.subreddit_cmd == "posts":
        sort = args.sort
        if sort == "new":
            items = sub.new(limit=limit)
        elif sort == "top":
            items = sub.top(limit=limit, time_filter=args.time)
        else:
            items = sub.hot(limit=limit)
    elif args.subreddit_cmd == "hot":
        items = sub.hot(limit=limit)
    elif args.subreddit_cmd == "new":
        items = sub.new(limit=limit)
    elif args.subreddit_cmd == "top":
        items = sub.top(limit=limit, time_filter=args.time)
    else:
        raise CliError(f"Unsupported subreddit command: {args.subreddit_cmd}")

    out = {
        "subreddit": args.subreddit,
        "mode": args.subreddit_cmd,
        "items": _collect_submissions(items),
    }
    emit(out, args.json)


def cmd_subreddit_subscription(args: argparse.Namespace) -> None:
    require_oauth_for(f"subreddit {args.subreddit_cmd}")

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)
    sub = reddit.subreddit(args.name)

    if args.subreddit_cmd == "subscribe":
        sub.subscribe()
        action = "subscribed"
    else:
        sub.unsubscribe()
        action = "unsubscribed"

    emit({"ok": True, "action": action, "subreddit": args.name}, args.json)


def flatten_comment_tree(children: list[dict[str, Any]], out: list[dict[str, Any]], limit: int) -> None:
    for child in children:
        if len(out) >= limit:
            return

        kind = child.get("kind")
        data = child.get("data", {})
        if kind == "t1" and isinstance(data, dict):
            out.append(serialize_comment_data(data))
            if len(out) >= limit:
                return

            replies = data.get("replies")
            if isinstance(replies, dict):
                reply_children = replies.get("data", {}).get("children", [])
                if isinstance(reply_children, list):
                    flatten_comment_tree(reply_children, out, limit)


def post_json_url_from_ref(post_ref: str) -> str:
    if post_ref.startswith("http://") or post_ref.startswith("https://"):
        url = post_ref
        if not url.endswith(".json"):
            url = url.rstrip("/") + ".json"
        return url

    kind, value = parse_reddit_ref(post_ref)
    if kind == "comment":
        raise CliError("post thread expects a submission reference, not a comment reference.")

    sub_id = value[3:] if value.startswith("t3_") else value
    return f"https://www.reddit.com/comments/{sub_id}.json"


def cmd_post_thread_public(args: argparse.Namespace) -> None:
    limit = ensure_positive_limit(args.limit)
    url = post_json_url_from_ref(args.post_ref)

    payload = public_get_json(url, {"limit": limit})
    if not isinstance(payload, list) or len(payload) < 2:
        raise CliError("Unexpected Reddit thread payload shape.")

    listing_submission = payload[0]
    listing_comments = payload[1]

    submission_children = listing_children(listing_submission)
    if not submission_children:
        raise CliError("Submission not found.")

    submission = serialize_submission_data(submission_children[0])

    comment_items: list[dict[str, Any]] = []
    raw_comment_children = listing_comments.get("data", {}).get("children", [])
    if isinstance(raw_comment_children, list):
        flatten_comment_tree(raw_comment_children, comment_items, limit)

    out = {
        "submission": submission,
        "comments": comment_items,
    }
    emit(out, args.json)


def cmd_post_thread(args: argparse.Namespace) -> None:
    if prefer_public_mode():
        cmd_post_thread_public(args)
        return

    cfg = load_config(require_user_auth=False)
    reddit = build_reddit(cfg, require_user_auth=False)
    limit = ensure_positive_limit(args.limit)

    submission = load_submission(reddit, args.post_ref)
    submission.comments.replace_more(limit=0)
    comments = []
    for idx, comment in enumerate(submission.comments.list()):
        if idx >= limit:
            break
        comments.append(serialize_comment(comment))

    out = {
        "submission": serialize_submission(submission),
        "comments": comments,
    }
    emit(out, args.json)


def cmd_post_create(args: argparse.Namespace) -> None:
    require_oauth_for("post create")

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)

    if not args.body and not args.url:
        raise CliError("Provide at least one of --body or --url for post create.")

    subreddit = reddit.subreddit(args.subreddit)
    if args.url:
        created = subreddit.submit(
            title=args.title,
            url=args.url,
            nsfw=args.nsfw,
            spoiler=args.spoiler,
            send_replies=True,
        )
    else:
        created = subreddit.submit(
            title=args.title,
            selftext=args.body,
            nsfw=args.nsfw,
            spoiler=args.spoiler,
            send_replies=True,
        )

    emit({"ok": True, "post": serialize_submission(created)}, args.json)


def cmd_search_public(args: argparse.Namespace) -> None:
    limit = ensure_positive_limit(args.limit)

    params: dict[str, Any] = {
        "q": args.query,
        "sort": args.sort,
        "t": args.time,
        "limit": limit,
        "type": "link",
    }
    if args.subreddit:
        path = f"/r/{args.subreddit}/search.json"
        params["restrict_sr"] = 1
    else:
        path = "/search.json"

    listing = public_get_json(path, params)
    items = [serialize_submission_data(item) for item in listing_children(listing)]

    out = {
        "query": args.query,
        "subreddit": args.subreddit or "all",
        "items": items,
    }
    emit(out, args.json)


def cmd_search(args: argparse.Namespace) -> None:
    if prefer_public_mode():
        cmd_search_public(args)
        return

    cfg = load_config(require_user_auth=False)
    reddit = build_reddit(cfg, require_user_auth=False)
    limit = ensure_positive_limit(args.limit)

    target = reddit.subreddit(args.subreddit) if args.subreddit else reddit.subreddit("all")
    items = target.search(args.query, sort=args.sort, time_filter=args.time, limit=limit)

    out = {
        "query": args.query,
        "subreddit": args.subreddit or "all",
        "items": _collect_submissions(items),
    }
    emit(out, args.json)


def cmd_user_profile_public(args: argparse.Namespace) -> None:
    payload = public_get_json(f"/user/{args.username}/about.json")
    data = payload.get("data", {})

    out = {
        "name": data.get("name") or args.username,
        "id": data.get("id"),
        "comment_karma": data.get("comment_karma"),
        "link_karma": data.get("link_karma"),
        "created_utc": iso_utc(data.get("created_utc")),
        "is_employee": data.get("is_employee"),
        "is_mod": data.get("is_mod"),
        "is_gold": data.get("is_gold"),
        "has_verified_email": data.get("has_verified_email"),
    }
    emit(out, args.json)


def cmd_user_profile(args: argparse.Namespace) -> None:
    if prefer_public_mode():
        cmd_user_profile_public(args)
        return

    cfg = load_config(require_user_auth=False)
    reddit = build_reddit(cfg, require_user_auth=False)

    redditor = reddit.redditor(args.username)
    _ = redditor.id

    out = {
        "name": str(redditor),
        "id": redditor.id,
        "comment_karma": redditor.comment_karma,
        "link_karma": redditor.link_karma,
        "created_utc": iso_utc(redditor.created_utc),
        "is_employee": getattr(redditor, "is_employee", None),
        "is_mod": getattr(redditor, "is_mod", None),
        "is_gold": getattr(redditor, "is_gold", None),
    }
    emit(out, args.json)


def cmd_user_comments_public(args: argparse.Namespace) -> None:
    limit = ensure_positive_limit(args.limit)
    listing = public_get_json(f"/user/{args.username}/comments.json", {"limit": limit})
    items = [serialize_comment_data(item) for item in listing_children(listing)]
    out = {
        "username": args.username,
        "items": items,
    }
    emit(out, args.json)


def cmd_user_comments(args: argparse.Namespace) -> None:
    if prefer_public_mode():
        cmd_user_comments_public(args)
        return

    cfg = load_config(require_user_auth=False)
    reddit = build_reddit(cfg, require_user_auth=False)
    limit = ensure_positive_limit(args.limit)

    redditor = reddit.redditor(args.username)
    items = redditor.comments.new(limit=limit)

    out = {
        "username": args.username,
        "items": _collect_comments(items),
    }
    emit(out, args.json)


def cmd_user_posts_public(args: argparse.Namespace) -> None:
    limit = ensure_positive_limit(args.limit)
    listing = public_get_json(f"/user/{args.username}/submitted.json", {"limit": limit})
    items = [serialize_submission_data(item) for item in listing_children(listing)]
    out = {
        "username": args.username,
        "items": items,
    }
    emit(out, args.json)


def cmd_user_posts(args: argparse.Namespace) -> None:
    if prefer_public_mode():
        cmd_user_posts_public(args)
        return

    cfg = load_config(require_user_auth=False)
    reddit = build_reddit(cfg, require_user_auth=False)
    limit = ensure_positive_limit(args.limit)

    redditor = reddit.redditor(args.username)
    items = redditor.submissions.new(limit=limit)

    out = {
        "username": args.username,
        "items": _collect_submissions(items),
    }
    emit(out, args.json)


def _collect_inbox(items: Iterable[Any]) -> list[dict[str, Any]]:
    return [serialize_item(item) for item in items]


def cmd_inbox(args: argparse.Namespace) -> None:
    require_oauth_for("inbox")

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)
    limit = ensure_positive_limit(args.limit)
    out = _collect_inbox(reddit.inbox.inbox(limit=limit))
    emit({"items": out}, args.json)


def cmd_mentions(args: argparse.Namespace) -> None:
    require_oauth_for("mentions")

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)
    limit = ensure_positive_limit(args.limit)
    out = _collect_inbox(reddit.inbox.mentions(limit=limit))
    emit({"items": out}, args.json)


def cmd_saved(args: argparse.Namespace) -> None:
    require_oauth_for("saved")

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)
    limit = ensure_positive_limit(args.limit)
    me = reddit.user.me()
    if me is None:
        raise CliError("Saved requires authenticated user.")
    items = [serialize_item(item) for item in me.saved(limit=limit)]
    emit({"items": items}, args.json)


def cmd_comment_reply(args: argparse.Namespace) -> None:
    require_oauth_for("comment reply")

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)

    thing = load_thing(reddit, args.thing_ref)
    created = thing.reply(args.text)
    emit({"ok": True, "comment": serialize_comment(created)}, args.json)


def cmd_comment_edit(args: argparse.Namespace) -> None:
    require_oauth_for("comment edit")

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)

    comment = load_comment(reddit, args.comment_ref)
    comment.edit(args.text)
    emit({"ok": True, "comment": serialize_comment(comment)}, args.json)


def cmd_vote(args: argparse.Namespace) -> None:
    require_oauth_for("vote")

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)

    thing = load_thing(reddit, args.thing_ref)

    if args.direction == "up":
        thing.upvote()
    elif args.direction == "down":
        thing.downvote()
    else:
        thing.clear_vote()

    emit(
        {
            "ok": True,
            "direction": args.direction,
            "thing": serialize_item(thing),
        },
        args.json,
    )


def cmd_save(args: argparse.Namespace) -> None:
    require_oauth_for(args.command)

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)

    thing = load_thing(reddit, args.thing_ref)
    if args.command == "save":
        thing.save()
        action = "saved"
    else:
        thing.unsave()
        action = "unsaved"

    emit({"ok": True, "action": action, "thing": serialize_item(thing)}, args.json)


def cmd_message_send(args: argparse.Namespace) -> None:
    require_oauth_for("message send")

    cfg = load_config(require_user_auth=True)
    reddit = build_reddit(cfg, require_user_auth=True)

    reddit.redditor(args.to).message(subject=args.subject, message=args.body)
    emit({"ok": True, "to": args.to, "subject": args.subject}, args.json)


def add_json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Output JSON.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reddit-cli",
        description="Deterministic Reddit CLI (public read-only fallback + OAuth for writes)",
    )
    parser.add_argument("--version", action="version", version=f"reddit-cli {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    auth = sub.add_parser("auth", help="Authentication commands")
    auth_sub = auth.add_subparsers(dest="auth_cmd", required=True)
    auth_check = auth_sub.add_parser("check", help="Validate auth/public-read configuration")
    add_json_flag(auth_check)

    whoami = sub.add_parser("whoami", help="Show authenticated account")
    add_json_flag(whoami)

    subreddit = sub.add_parser("subreddit", help="Subreddit operations")
    subreddit_sub = subreddit.add_subparsers(dest="subreddit_cmd", required=True)

    sr_posts = subreddit_sub.add_parser("posts", help="List posts")
    sr_posts.add_argument("subreddit")
    sr_posts.add_argument("--sort", choices=["hot", "new", "top"], default="hot")
    sr_posts.add_argument("--time", choices=["all", "day", "hour", "month", "week", "year"], default="week")
    sr_posts.add_argument("--limit", type=int, default=10)
    add_json_flag(sr_posts)

    sr_hot = subreddit_sub.add_parser("hot", help="List hot posts")
    sr_hot.add_argument("subreddit")
    sr_hot.add_argument("--limit", type=int, default=10)
    add_json_flag(sr_hot)

    sr_new = subreddit_sub.add_parser("new", help="List new posts")
    sr_new.add_argument("subreddit")
    sr_new.add_argument("--limit", type=int, default=10)
    add_json_flag(sr_new)

    sr_top = subreddit_sub.add_parser("top", help="List top posts")
    sr_top.add_argument("subreddit")
    sr_top.add_argument("--time", choices=["all", "day", "hour", "month", "week", "year"], default="week")
    sr_top.add_argument("--limit", type=int, default=10)
    add_json_flag(sr_top)

    sr_subscribe = subreddit_sub.add_parser("subscribe", help="Subscribe to subreddit (OAuth only)")
    sr_subscribe.add_argument("name")
    add_json_flag(sr_subscribe)

    sr_unsubscribe = subreddit_sub.add_parser("unsubscribe", help="Unsubscribe from subreddit (OAuth only)")
    sr_unsubscribe.add_argument("name")
    add_json_flag(sr_unsubscribe)

    post = sub.add_parser("post", help="Post operations")
    post_sub = post.add_subparsers(dest="post_cmd", required=True)

    post_thread = post_sub.add_parser("thread", help="Fetch post and comments")
    post_thread.add_argument("post_ref", help="Submission ID or URL")
    post_thread.add_argument("--limit", type=int, default=20)
    add_json_flag(post_thread)

    post_create = post_sub.add_parser("create", help="Create a new post (OAuth only)")
    post_create.add_argument("--subreddit", required=True)
    post_create.add_argument("--title", required=True)
    post_create.add_argument("--body", default=None)
    post_create.add_argument("--url", default=None)
    post_create.add_argument("--nsfw", action="store_true")
    post_create.add_argument("--spoiler", action="store_true")
    add_json_flag(post_create)

    search = sub.add_parser("search", help="Search submissions")
    search.add_argument("query")
    search.add_argument("--subreddit", default=None)
    search.add_argument("--sort", choices=["relevance", "hot", "new", "top", "comments"], default="relevance")
    search.add_argument("--time", choices=["all", "day", "hour", "month", "week", "year"], default="all")
    search.add_argument("--limit", type=int, default=10)
    add_json_flag(search)

    user = sub.add_parser("user", help="User profile/history operations")
    user_sub = user.add_subparsers(dest="user_cmd", required=True)

    user_profile = user_sub.add_parser("profile", help="Get user profile")
    user_profile.add_argument("username")
    add_json_flag(user_profile)

    user_comments = user_sub.add_parser("comments", help="Get user comments")
    user_comments.add_argument("username")
    user_comments.add_argument("--limit", type=int, default=20)
    add_json_flag(user_comments)

    user_posts = user_sub.add_parser("posts", help="Get user posts")
    user_posts.add_argument("username")
    user_posts.add_argument("--limit", type=int, default=20)
    add_json_flag(user_posts)

    inbox = sub.add_parser("inbox", help="Fetch inbox items (OAuth only)")
    inbox.add_argument("--limit", type=int, default=20)
    add_json_flag(inbox)

    mentions = sub.add_parser("mentions", help="Fetch mentions (OAuth only)")
    mentions.add_argument("--limit", type=int, default=20)
    add_json_flag(mentions)

    saved = sub.add_parser("saved", help="Fetch saved items (OAuth only)")
    saved.add_argument("--limit", type=int, default=20)
    add_json_flag(saved)

    comment = sub.add_parser("comment", help="Comment operations (OAuth only)")
    comment_sub = comment.add_subparsers(dest="comment_cmd", required=True)

    comment_reply = comment_sub.add_parser("reply", help="Reply to submission or comment (OAuth only)")
    comment_reply.add_argument("thing_ref", help="Comment/submission ID or URL")
    comment_reply.add_argument("--text", required=True)
    add_json_flag(comment_reply)

    comment_edit = comment_sub.add_parser("edit", help="Edit an existing comment (OAuth only)")
    comment_edit.add_argument("comment_ref", help="Comment ID or URL")
    comment_edit.add_argument("--text", required=True)
    add_json_flag(comment_edit)

    vote = sub.add_parser("vote", help="Vote on a submission/comment (OAuth only)")
    vote.add_argument("direction", choices=["up", "down", "clear"])
    vote.add_argument("thing_ref", help="Comment/submission ID or URL")
    add_json_flag(vote)

    save = sub.add_parser("save", help="Save a submission/comment (OAuth only)")
    save.add_argument("thing_ref", help="Comment/submission ID or URL")
    add_json_flag(save)

    unsave = sub.add_parser("unsave", help="Unsave a submission/comment (OAuth only)")
    unsave.add_argument("thing_ref", help="Comment/submission ID or URL")
    add_json_flag(unsave)

    message = sub.add_parser("message", help="Direct message operations (OAuth only)")
    message_sub = message.add_subparsers(dest="message_cmd", required=True)

    message_send = message_sub.add_parser("send", help="Send a private message (OAuth only)")
    message_send.add_argument("--to", required=True)
    message_send.add_argument("--subject", required=True)
    message_send.add_argument("--body", required=True)
    add_json_flag(message_send)

    return parser


def dispatch(args: argparse.Namespace) -> None:
    if args.command == "auth" and args.auth_cmd == "check":
        cmd_auth_check(args)
        return

    if args.command == "whoami":
        cmd_whoami(args)
        return

    if args.command == "subreddit":
        if args.subreddit_cmd in {"posts", "hot", "new", "top"}:
            cmd_subreddit_read(args)
            return
        if args.subreddit_cmd in {"subscribe", "unsubscribe"}:
            cmd_subreddit_subscription(args)
            return

    if args.command == "post" and args.post_cmd == "thread":
        cmd_post_thread(args)
        return

    if args.command == "post" and args.post_cmd == "create":
        cmd_post_create(args)
        return

    if args.command == "search":
        cmd_search(args)
        return

    if args.command == "user" and args.user_cmd == "profile":
        cmd_user_profile(args)
        return

    if args.command == "user" and args.user_cmd == "comments":
        cmd_user_comments(args)
        return

    if args.command == "user" and args.user_cmd == "posts":
        cmd_user_posts(args)
        return

    if args.command == "inbox":
        cmd_inbox(args)
        return

    if args.command == "mentions":
        cmd_mentions(args)
        return

    if args.command == "saved":
        cmd_saved(args)
        return

    if args.command == "comment" and args.comment_cmd == "reply":
        cmd_comment_reply(args)
        return

    if args.command == "comment" and args.comment_cmd == "edit":
        cmd_comment_edit(args)
        return

    if args.command == "vote":
        cmd_vote(args)
        return

    if args.command in {"save", "unsave"}:
        cmd_save(args)
        return

    if args.command == "message" and args.message_cmd == "send":
        cmd_message_send(args)
        return

    raise CliError("Unsupported command combination.")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        dispatch(args)
        return 0
    except CliError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except RedditAPIException as exc:
        print(f"ERROR: Reddit API error: {exc}", file=sys.stderr)
        return 2
    except (PrawcoreException, OAuthException) as exc:
        print(f"ERROR: Auth/network error: {exc}", file=sys.stderr)
        return 2
    except requests.RequestException as exc:
        print(f"ERROR: HTTP error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
