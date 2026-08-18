export const sourceZh = {
  "source.browser": "浏览器",
  "source.desktop": "桌面应用",
  "source.terminal": "终端",
  "source.script": "脚本",
  "source.mobile": "移动设备",
  "source.iot": "IoT",
  "source.reverse": "免代理接入",
} as const;

export const sourceEn = {
  "source.browser": "Browser",
  "source.desktop": "Desktop app",
  "source.terminal": "Terminal",
  "source.script": "Script",
  "source.mobile": "Mobile",
  "source.iot": "IoT",
  "source.reverse": "Reverse proxy",
} as const satisfies Record<keyof typeof sourceZh, string>;
