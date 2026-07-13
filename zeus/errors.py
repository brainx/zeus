from __future__ import annotations


class ZeusConflictError(RuntimeError):
    code = "conflict"


class BotExistsError(ZeusConflictError):
    code = "bot_exists"


class BotRunningError(ZeusConflictError):
    code = "bot_running"


class BotReplaceError(ZeusConflictError):
    code = "bot_replace_failed"


class BotDeleteError(ZeusConflictError):
    code = "bot_delete_failed"


class BotArchiveError(ZeusConflictError):
    code = "bot_archive_failed"
