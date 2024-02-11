Output demo/basic.gif

Require klp

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 600
Set Margin 0

Type "klp examples/mylog.logfmt" Sleep 200ms  Enter
Sleep 3s
Type "klp -c examples/mylog.logfmt" Sleep 200ms  Enter
Sleep 3s
Type "cat examples/mylog.logfmt | klp -S" Sleep 2s  Enter
Sleep 10s

