#!/usr/bin/env bash
set -uo pipefail

adb wait-for-device
ready=0
for attempt in $(seq 1 120); do
  if adb shell pm path android >/dev/null 2>&1 &&
    adb shell am get-current-user >/dev/null 2>&1; then
    sleep 5
    if adb shell pm path android >/dev/null 2>&1 &&
      adb shell am get-current-user >/dev/null 2>&1; then
      ready=1
      break
    fi
  fi
  sleep 3
done

if [[ "$ready" != 1 ]]; then
  echo "Android package and activity services did not become stable" >&2
  exit 1
fi

results_dir="android/bridge/build/outputs/androidTest-results/connected"
mkdir -p "$results_dir"
adb logcat -c || true

set +e
(
  cd android
  gradle --no-daemon :bridge:connectedDebugAndroidTest
) > "$RUNNER_TEMP/kononexus-instrumentation-1.log" 2>&1
first_status=$?
set -e
cat "$RUNNER_TEMP/kononexus-instrumentation-1.log"

if [[ "$first_status" -eq 0 ]]; then
  exit 0
fi
if ! grep -Fq "Instrumentation run failed due to Process crashed."   "$RUNNER_TEMP/kononexus-instrumentation-1.log"; then
  exit "$first_status"
fi

echo "Instrumentation process crashed before tests; capturing logcat and retrying once."
adb logcat -d -v threadtime > "$results_dir/process-crash-logcat.txt" || true
adb shell am force-stop com.swir.kononexus.test || true
adb shell am force-stop com.swir.kononexus || true
adb shell pm clear com.swir.kononexus.test || true
adb shell pm clear com.swir.kononexus || true
sleep 5

cd android
gradle --no-daemon :bridge:connectedDebugAndroidTest
