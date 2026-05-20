const TELEMETRY_PACKAGES = {
  "com.miui.analytics": {
    name: "MIUI Analytics",
    vendor: "Xiaomi",
    risk: "high",
    category: "OEM analytics",
    summary: "Known Xiaomi analytics and telemetry component.",
    recommendation: "Review before disabling. Some MIUI diagnostics may stop working.",
    command: "adb shell pm disable-user --user 0 com.miui.analytics"
  },
  "com.miui.msa.global": {
    name: "MIUI System Ads",
    vendor: "Xiaomi",
    risk: "high",
    category: "System ads",
    summary: "MIUI advertising service commonly associated with system ads.",
    recommendation: "Usually safe to review for disabling on many Xiaomi devices.",
    command: "adb shell pm disable-user --user 0 com.miui.msa.global"
  },
  "com.xiaomi.mipicks": {
    name: "GetApps",
    vendor: "Xiaomi",
    risk: "medium",
    category: "App store telemetry",
    summary: "Xiaomi app store component that can participate in recommendations and app telemetry.",
    recommendation: "Review if you do not use Xiaomi's app store.",
    command: "adb shell pm disable-user --user 0 com.xiaomi.mipicks"
  },
  "com.samsung.android.dqagent": {
    name: "Samsung Device Quality Agent",
    vendor: "Samsung",
    risk: "medium",
    category: "Diagnostics",
    summary: "Samsung diagnostics and quality reporting component.",
    recommendation: "Review impact before disabling because it may be tied to device support diagnostics.",
    command: "adb shell pm disable-user --user 0 com.samsung.android.dqagent"
  },
  "com.sec.android.diagmonagent": {
    name: "Samsung Diagnostics Monitor",
    vendor: "Samsung",
    risk: "medium",
    category: "Diagnostics",
    summary: "Samsung diagnostic monitoring component.",
    recommendation: "Review before disabling. Diagnostics and support reporting may be affected.",
    command: "adb shell pm disable-user --user 0 com.sec.android.diagmonagent"
  },
  "com.samsung.android.samsungpassautofill": {
    name: "Samsung Pass Autofill",
    vendor: "Samsung",
    risk: "low",
    category: "Identity service",
    summary: "Autofill component with sensitive account and form access when enabled.",
    recommendation: "Keep only if you actively use Samsung Pass.",
    command: "adb shell pm disable-user --user 0 com.samsung.android.samsungpassautofill"
  },
  "com.heytap.mcs": {
    name: "HeyTap Cloud Service",
    vendor: "Oppo/Realme/OnePlus",
    risk: "medium",
    category: "Vendor cloud",
    summary: "Vendor service that may participate in account, push, or telemetry features.",
    recommendation: "Review carefully because push notifications or account sync may depend on it.",
    command: "adb shell pm disable-user --user 0 com.heytap.mcs"
  },
  "com.heytap.market": {
    name: "HeyTap App Market",
    vendor: "Oppo/Realme/OnePlus",
    risk: "medium",
    category: "App store telemetry",
    summary: "Vendor app store that can participate in recommendations and usage telemetry.",
    recommendation: "Review if you only use Google Play or another trusted app source.",
    command: "adb shell pm disable-user --user 0 com.heytap.market"
  },
  "com.coloros.statistics.rom": {
    name: "ColorOS Statistics",
    vendor: "Oppo/Realme/OnePlus",
    risk: "high",
    category: "OEM analytics",
    summary: "ColorOS statistics and telemetry package.",
    recommendation: "Review as a strong telemetry candidate.",
    command: "adb shell pm disable-user --user 0 com.coloros.statistics.rom"
  },
  "com.vivo.daemonService": {
    name: "Vivo Daemon Service",
    vendor: "Vivo",
    risk: "medium",
    category: "Vendor service",
    summary: "Vivo background vendor service that may participate in analytics or device services.",
    recommendation: "Review impact before disabling.",
    command: "adb shell pm disable-user --user 0 com.vivo.daemonService"
  },
  "com.huawei.hwid": {
    name: "Huawei Mobile Services",
    vendor: "Huawei",
    risk: "medium",
    category: "Vendor cloud",
    summary: "Huawei identity and mobile services package.",
    recommendation: "Only disable if you understand Huawei account and service impact.",
    command: "adb shell pm disable-user --user 0 com.huawei.hwid"
  },
  "com.facebook.appmanager": {
    name: "Meta App Manager",
    vendor: "Meta",
    risk: "high",
    category: "Third-party telemetry",
    summary: "Meta background app management component often preinstalled on OEM devices.",
    recommendation: "Review if you do not rely on preinstalled Meta app integrations.",
    command: "adb shell pm disable-user --user 0 com.facebook.appmanager"
  },
  "com.facebook.services": {
    name: "Meta Services",
    vendor: "Meta",
    risk: "high",
    category: "Third-party telemetry",
    summary: "Meta service package commonly bundled with Facebook-related apps.",
    recommendation: "Review if you do not use Meta apps or background integrations.",
    command: "adb shell pm disable-user --user 0 com.facebook.services"
  },
  "com.facebook.system": {
    name: "Meta System",
    vendor: "Meta",
    risk: "high",
    category: "Third-party telemetry",
    summary: "Meta system integration package commonly preinstalled by device vendors.",
    recommendation: "Review if you do not want preinstalled Meta services active.",
    command: "adb shell pm disable-user --user 0 com.facebook.system"
  },
  "com.google.android.gms.location.history": {
    name: "Google Location History",
    vendor: "Google",
    risk: "medium",
    category: "Location telemetry",
    summary: "Google component associated with location history and location telemetry services.",
    recommendation: "Review Google account location settings before disabling package-level services.",
    command: "adb shell pm disable-user --user 0 com.google.android.gms.location.history"
  },
  "com.google.android.feedback": {
    name: "Google Feedback",
    vendor: "Google",
    risk: "low",
    category: "Diagnostics",
    summary: "Google feedback and diagnostic reporting component.",
    recommendation: "Review if you do not use Android feedback or diagnostic reporting.",
    command: "adb shell pm disable-user --user 0 com.google.android.feedback"
  },
  "com.google.android.partnersetup": {
    name: "Google Partner Setup",
    vendor: "Google",
    risk: "medium",
    category: "Vendor integration",
    summary: "Google/OEM partner setup component used for device provisioning and integrations.",
    recommendation: "Review carefully because provisioning or partner integrations may be affected.",
    command: "adb shell pm disable-user --user 0 com.google.android.partnersetup"
  },
  "com.oplus.statistics.rom": {
    name: "OPlus Statistics",
    vendor: "Oppo/Realme/OnePlus",
    risk: "high",
    category: "OEM analytics",
    summary: "OPlus statistics and telemetry package.",
    recommendation: "Review as a strong OEM telemetry candidate.",
    command: "adb shell pm disable-user --user 0 com.oplus.statistics.rom"
  },
  "com.oplus.deepthinker": {
    name: "OPlus DeepThinker",
    vendor: "Oppo/Realme/OnePlus",
    risk: "medium",
    category: "Behavior services",
    summary: "Vendor intelligence service that may support app prediction, usage learning, or device optimization.",
    recommendation: "Review impact before disabling because device optimization features may be affected.",
    command: "adb shell pm disable-user --user 0 com.oplus.deepthinker"
  },
  "com.heytap.browser": {
    name: "HeyTap Browser",
    vendor: "Oppo/Realme/OnePlus",
    risk: "medium",
    category: "Browser telemetry",
    summary: "Vendor browser that may include recommendations, analytics, and search telemetry.",
    recommendation: "Review if you use another browser and do not need the vendor browser.",
    command: "adb shell pm disable-user --user 0 com.heytap.browser"
  },
  "com.coloros.weather.service": {
    name: "ColorOS Weather Service",
    vendor: "Oppo/Realme/OnePlus",
    risk: "low",
    category: "Location service",
    summary: "Weather service that may use location or network lookups for forecasts.",
    recommendation: "Review if weather location updates are unnecessary.",
    command: "adb shell pm disable-user --user 0 com.coloros.weather.service"
  },
  "com.vivo.pushservice": {
    name: "Vivo Push Service",
    vendor: "Vivo",
    risk: "medium",
    category: "Vendor push",
    summary: "Vivo push service that can support background vendor messaging and app notifications.",
    recommendation: "Review carefully because notifications may be affected.",
    command: "adb shell pm disable-user --user 0 com.vivo.pushservice"
  },
  "com.huawei.android.pushagent": {
    name: "Huawei Push Agent",
    vendor: "Huawei",
    risk: "medium",
    category: "Vendor push",
    summary: "Huawei push service used by Huawei Mobile Services and some apps.",
    recommendation: "Review carefully because notifications may be affected.",
    command: "adb shell pm disable-user --user 0 com.huawei.android.pushagent"
  },
  "com.amazon.mShop.android.shopping": {
    name: "Amazon Shopping",
    vendor: "Amazon",
    risk: "low",
    category: "Retail telemetry",
    summary: "Retail app that may include recommendations, ads, and shopping analytics.",
    recommendation: "Review app permissions if installed but unused.",
    command: "adb shell pm disable-user --user 0 com.amazon.mShop.android.shopping"
  }
};

const TRACKING_SIGNALS = [
  {
    id: "notification_listeners",
    title: "Notification listeners",
    risk: "high",
    category: "Sensitive access",
    summary: "Apps with notification access can read notification content, including message previews and one-time codes.",
    command: ["shell", "settings", "get", "secure", "enabled_notification_listeners"]
  },
  {
    id: "accessibility_services",
    title: "Accessibility services",
    risk: "high",
    category: "Sensitive access",
    summary: "Accessibility services can observe and control parts of the screen, making them one of Android's most sensitive permissions.",
    command: ["shell", "settings", "get", "secure", "enabled_accessibility_services"]
  },
  {
    id: "usage_access",
    title: "Usage access",
    risk: "medium",
    category: "Behavior tracking",
    summary: "Usage access lets apps inspect which apps you use and when you use them.",
    command: ["shell", "cmd", "appops", "query-op", "GET_USAGE_STATS", "allow"]
  },
  {
    id: "fine_location",
    title: "Precise location access",
    risk: "medium",
    category: "Location tracking",
    summary: "Precise location access can be used to build detailed movement and habit profiles.",
    command: ["shell", "cmd", "appops", "query-op", "android:fine_location", "allow"]
  },
  {
    id: "coarse_location",
    title: "Approximate location access",
    risk: "medium",
    category: "Location tracking",
    summary: "Approximate location can still reveal city-level habits and routine places.",
    command: ["shell", "cmd", "appops", "query-op", "android:coarse_location", "allow"]
  }
];

const PERMISSION_AUDIT_OPS = [
  {
    id: "camera",
    label: "Camera",
    risk: 2,
    op: "android:camera",
    permission: "android.permission.CAMERA",
    summary: "Can access the camera when permission conditions are met."
  },
  {
    id: "microphone",
    label: "Microphone",
    risk: 2,
    op: "android:record_audio",
    permission: "android.permission.RECORD_AUDIO",
    summary: "Can access the microphone when permission conditions are met."
  },
  {
    id: "fine_location",
    label: "Precise location",
    risk: 2,
    op: "android:fine_location",
    permission: "android.permission.ACCESS_FINE_LOCATION",
    summary: "Can access precise GPS-level location."
  },
  {
    id: "coarse_location",
    label: "Approximate location",
    risk: 1,
    op: "android:coarse_location",
    permission: "android.permission.ACCESS_COARSE_LOCATION",
    summary: "Can access approximate location."
  },
  {
    id: "contacts",
    label: "Contacts",
    risk: 2,
    op: "android:read_contacts",
    permission: "android.permission.READ_CONTACTS",
    summary: "Can read the contacts list."
  },
  {
    id: "sms",
    label: "SMS",
    risk: 3,
    op: "android:read_sms",
    permission: "android.permission.READ_SMS",
    summary: "Can read SMS messages."
  },
  {
    id: "phone_state",
    label: "Phone state",
    risk: 1,
    op: "android:read_phone_state",
    permission: "android.permission.READ_PHONE_STATE",
    summary: "Can read phone and network identity details."
  },
  {
    id: "overlay",
    label: "Display over apps",
    risk: 2,
    op: "android:system_alert_window",
    summary: "Can draw overlays on top of other apps."
  },
  {
    id: "usage_access",
    label: "Usage access",
    risk: 2,
    op: "GET_USAGE_STATS",
    summary: "Can inspect app usage patterns."
  }
];

module.exports = {
  TELEMETRY_PACKAGES,
  TRACKING_SIGNALS,
  PERMISSION_AUDIT_OPS
};
