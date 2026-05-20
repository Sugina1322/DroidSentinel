const APP_LABELS = {
  "com.instagram.android": "Instagram",
  "com.facebook.katana": "Facebook",
  "com.facebook.orca": "Messenger",
  "com.facebook.appmanager": "Meta App Manager",
  "com.facebook.services": "Meta Services",
  "com.facebook.system": "Meta System",
  "com.microsoft.teams": "Microsoft Teams",
  "com.microsoft.office.outlook": "Microsoft Outlook",
  "com.openai.chatgpt": "ChatGPT",
  "com.discord": "Discord",
  "org.telegram.messenger": "Telegram",
  "com.viber.voip": "Viber",
  "com.whatsapp": "WhatsApp",
  "us.zoom.videomeetings": "Zoom",
  "com.google.android.apps.maps": "Google Maps",
  "com.google.android.gm": "Gmail",
  "com.google.android.youtube": "YouTube",
  "com.android.chrome": "Chrome",
  "com.linkedin.android": "LinkedIn",
  "com.ss.android.ugc.trill": "TikTok",
  "com.shopee.ph": "Shopee",
  "com.lazada.android": "Lazada",
  "com.paymaya": "Maya",
  "ph.com.gotyme": "GoTyme Bank",
  "org.zwanoo.android.speedtest": "Speedtest",
  "com.tplink.iot": "TP-Link Tapo",
  "com.intsig.camscanner": "CamScanner",
  "host.exp.exponent": "Expo Go"
};

function labelForPackage(packageName) {
  if (APP_LABELS[packageName]) return APP_LABELS[packageName];

  const ignored = new Set(["android", "app", "apps", "mobile", "main", "free", "paid"]);
  const segments = packageName
    .split(".")
    .filter((segment) => segment && !ignored.has(segment.toLowerCase()));
  const lastSegment = segments.at(-1) || packageName;
  return lastSegment
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

module.exports = {
  APP_LABELS,
  labelForPackage
};
