Require klp

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 800
Set Margin 0

Type "klp examples/mylog.logfmt" Enter
Enter
Type "klp -c examples/mylog.logfmt" Enter
Enter
Type "cat examples/mylog.logfmt | klp -S" Enter

Sleep 1s
Screenshot demo/basic.png
