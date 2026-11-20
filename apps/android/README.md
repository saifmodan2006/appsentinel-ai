# Android companion

Use JDK 17, Gradle 8.9, Android SDK Platform 35, and Build Tools 35.0.0. Set `JAVA_HOME` and `ANDROID_HOME` to the respective installation directories. Accept SDK terms through your local Android SDK setup before running the build.

```sh
gradle -p apps/android assembleDebug lintDebug
```

The debug build is written to `apps/android/app/build/outputs/apk/debug/app-debug.apk` after a successful build. An Android emulator can connect to the Docker dashboard through `http://10.0.2.2:8080`. Release builds require a normal HTTPS endpoint. A physical device must be able to reach the configured HTTPS server and trust its TLS certificate.

Create an account in the web dashboard, then sign in through the companion. The document picker grants access to the selected APK. Check its filename and size before consenting to upload. The app polls queued and running jobs and shows the stored report, findings, and recommendations. Sign-in tokens are held in memory and discarded on sign-out or process exit. The companion requires internet permission only.
