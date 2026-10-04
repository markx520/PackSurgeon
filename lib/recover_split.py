# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
命名兼容模块:
- 新代码建议从 lib.recover_split 导入 RecoverSplit
- 旧代码仍可继续使用 lib.Recoverspilt
"""

from lib.Recoverspilt import RecoverSpilt  # noqa: F401

# 规范命名别名
RecoverSplit = RecoverSpilt

