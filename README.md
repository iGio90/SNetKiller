very quick. the app uses frida to inject an agent into google services and prevent access to certain files.
this makes snet believe we are good guys and bypass safetynet attest on apps.
you can use logcat to see what files are currently accessed.
feel free to pr your patches to the agent if needed

you can install app-debug.apk and use the unique button available