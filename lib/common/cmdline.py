# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import argparse
import sys


class CommandLines():
    _cached_options = None
    _cached_argv = None

    def _build_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-u', '--url', dest='url', help='请输入目标 URL')
        parser.add_argument('-c', '--cookie', dest='cookie', help='请输入网站 Cookies')
        parser.add_argument('-d', '--head', dest='head', default='Cache-Control:no-cache', help='请输入额外的 HTTP 头')
        parser.add_argument('-l', '--list', dest='list', help='请输入目标 URL 列表文件')
        parser.add_argument('-p', '--proxy', dest='proxy', help='请输入代理地址')
        parser.add_argument('-j', '--js', dest='js', help='指定要分析的 JS URL（多个用逗号分隔）')

        parser.add_argument('-f', '--flag', dest='ssl_flag', default='1', help='SSL 安全标志')
        parser.add_argument('-s', '--silent', dest='silent', help='静默模式（自定义报告名称）')

        parser.add_argument('--finder', dest='finder', action='store_true', default=False, help='启用JavaScript敏感信息扫描')
        parser.add_argument('-T', '--url-timeout', dest='url_timeout', type=int, default=0,
                            help='单个URL的总扫描超时时间(秒)，0表示关闭。建议：普通站点 300~600 秒。')

        # Dynamic JS Discovery options (Requirements 1.1, 1.3, 2.1, 2.4)
        parser.add_argument('--browser', dest='browser', action='store_true', default=False,
                            help='启用无头浏览器模式以捕获动态加载的JS文件 (Enable headless browser mode)')
        parser.add_argument('--browser-timeout', dest='browser_timeout', type=int, default=10000,
                            help='浏览器等待超时时间(毫秒)，默认10000 (Browser timeout in ms, default 10000)')
        parser.add_argument('--max-iframe-depth', dest='max_iframe_depth', type=int, default=3,
                            help='iframe递归解析最大深度，默认3 (Max iframe recursion depth, default 3)')
        parser.add_argument('--no-iframe', dest='no_iframe', action='store_true', default=False,
                            help='禁用iframe递归解析 (Disable iframe recursive parsing)')
        parser.add_argument(
            '--dom-scan-max-chars',
            dest='dom_scan_max_chars',
            type=int,
            default=900000,
            help='DOM加载器正则扫描最大字符数，默认900000',
        )
        parser.add_argument('--dir', dest='dir', help='离线模式：直接分析本地已下载或解混淆的 JS 目录')
        return parser

    def cmd(self, argv=None):
        if argv is None:
            current_argv = tuple(sys.argv[1:])
            if CommandLines._cached_options is not None and CommandLines._cached_argv == current_argv:
                return CommandLines._cached_options
            parse_argv = list(current_argv)
        else:
            parse_argv = list(argv)

        parser = self._build_parser()
        options = parser.parse_args(parse_argv)
        if options.list is None and options.url is None and getattr(options, 'js', None) is None and getattr(options, 'dir', None) is None:
            parser.print_help()
            raise SystemExit(0)

        if argv is None:
            CommandLines._cached_options = options
            CommandLines._cached_argv = tuple(sys.argv[1:])
        return options


if __name__ == '__main__':
    print(CommandLines().cmd().cookie)
