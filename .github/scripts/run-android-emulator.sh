#!/usr/bin/env bash
set -uo pipefail

wait_for_android_services() {
  local attempts="${1:-120}"
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    if adb shell pm path android >/dev/null 2>&1 &&
      adb shell am get-current-user >/dev/null 2>&1; then
      sleep 5
      if adb shell pm path android >/dev/null 2>&1 &&
        adb shell am get-current-user >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 3
  done
  return 1
}

adb wait-for-device
if ! wait_for_android_services 120; then
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

failure_reason=""
if grep -Fq "Instrumentation run failed due to Process crashed."   "$RUNNER_TEMP/kononexus-instrumentation-1.log"; then
  failure_reason="instrumentation process crash"
elif grep -Fq "Failure calling service package: Broken pipe"   "$RUNNER_TEMP/kononexus-instrumentation-1.log"; then
  failure_reason="Android package service broken pipe"
else
  exit "$first_status"
fi

echo "Recoverable pre-test failure ($failure_reason); capturing logcat and retrying once."
adb logcat -d -v threadtime > "$results_dir/pre-test-infrastructure-failure-logcat.txt" || true
adb shell am force-stop com.swir.kononexus.test || true
adb shell am force-stop com.swir.kononexus || true
adb shell pm clear com.swir.kononexus.test || true
adb shell pm clear com.swir.kononexus || true

if ! wait_for_android_services 120; then
  echo "Android services did not recover after $failure_reason" >&2
  exit "$first_status"
fi

cd android
gradle --no-daemon :bridge:connectedDebugAndroidTest
