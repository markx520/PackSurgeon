# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os
from configparser import ConfigParser


class ReadConfig(object):

    def __init__(self):
        self.path = os.getcwd() + os.sep + "config.ini"  # 配置文件地址
        self.langPath = os.getcwd() + os.sep + "doc/lang.ini"  # 配置文件地址
        self.config = ConfigParser()

    def _read_value(self, file_path, sections, key):
        parser = ConfigParser()
        parser.read(file_path, encoding="utf-8")
        return parser[sections][key]

    def getValue(self, sections, key):
        return self._read_value(self.path, sections, key)

    def getLang(self, sections, key):
        return self._read_value(self.langPath, sections, key)
