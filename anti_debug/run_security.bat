adb push securityd /data/local/tmp/
adb shell su -c 'chmod 777 /data/local/tmp/securityd'
adb shell su -c 'chown root:root /data/local/tmp/securityd'

adb forward tcp:12345 tcp:12345
rem adb shell "/data/local/tmp/gdbserver  localhost:12345 /data/local/tmp/securityd"
adb shell "/data/local/tmp/securityd"
pause