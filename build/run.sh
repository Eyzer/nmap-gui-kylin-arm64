#!/bin/bash
# Nmap 图形界面启动脚本
DIR=/opt/nmapgui
export LD_LIBRARY_PATH="$DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export QT_AUTO_SCREEN_SCALE_FACTOR=1
if [ -z "$DISPLAY" ] && [ -z "$WAYLAND_DISPLAY" ]; then
    echo "未检测到图形会话，请在有桌面的环境中运行。" >&2
    exit 1
fi
if [ "$XDG_SESSION_TYPE" = "wayland" ]; then
    export QT_QPA_PLATFORM=xcb
fi
exec "$DIR/bin/nmapgui" "$@"
