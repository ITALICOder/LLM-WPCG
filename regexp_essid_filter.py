import re
import sys

TRASH_PATTERNS = [
    # ISP router auto-named SSIDs
    re.compile(r'(?i)^(tim[- .]?|vodafone[- .]?|fastweb[- .]?|wind[3]?[- .]?|windtre[- .]?|skywifi[_]?|enel[- .]?wifi|eolo[- .]?|iliadbox[- .]?|postemobile[_]?|home.?&.?life|infostrada[- .]?|telecom[- .]?|linkem[_]?|webpocket[- .]?|alice[- .]?|tiscali[- .]?|livebox[- .]?|movistar[_]?|orange[- .]?|sfr[- .]?|freebox[- .]?|bbox[- .]?|cosmote[- .]?|digi[- .]?|meo[- .]?|sunrise[_]?|adsl[- .]?_?inwi)'),

    # Car hotspots
    re.compile(r'(?i)^(audi_mmi_|bmw[ -]|mbux[ -]|mb[ -]hotspot|my bmw|my alfa romeo|vw[- ]|porsche[- ]|mazda[ -]|incarhotspot[- ]|carplay[- ]|mycar\d|my.car\d|mycar \d)'),
    re.compile(r'(?i)^my (seat|skoda|vw|mib|peugeot|jeep|cupra|fiat|ford|opel|citroen|ds|chevrolet|volvo)\b'),
    re.compile(r'^ADB-[0-9A-Fa-f]{6}'),

    # Phone model tethering
    re.compile(r'(?i)^(galaxy[ -]|iphone|redmi[ -]|oppo[ -]|realme[ -]|honor[ -]|moto[ e]|huawei[ -]|zte[ -]|samsung[ -]|xiaomi[ -]|oneplus[ -]|poco[ -]|vivo[ -]|infinix[ -]|pixel[ -]|mi [0-9])'),
    re.compile(r'(?i)^(smartphone_connect_|androidshare_|oplus_|hismart[- ])'),
    re.compile(r'(?i)^(android|ndroid)[\w]*'),
    re.compile(r'(?i)^androidap[\w]*'),
    re.compile(r'^AndroidAuto_\w+'),

    # Router/device brands (default SSIDs)
    re.compile(r'(?i)^(tp[- .]?link[- _]?|d[- .]?link[- _]?|tenda[_ ]|fritz!box|netgear|mercusys[_]?|zyxel[_]?|tapo[- _]?|miwifi[_]?|bticino[_]?|meross[_]?|mikrotik[_]?|ubiquiti[_]?)'),

    # Printer / DIRECT SSIDs
    re.compile(r'(?i)^direct[- \w]'),
    re.compile(r'(?i)^fritz!'),
    re.compile(r'(?i)^huawei_[beph]\w+_\w+'),
    re.compile(r'^SKY[0-9A-F]{4,}'),
    re.compile(r'(?i)^(teletu_|upc\d|infinitum)'),
    re.compile(r'(?i)^autonet[- ]'),
    re.compile(r'(?i)^autoreconnection_'),
    re.compile(r'^WiFi-\d{8}'),
    re.compile(r'^STARLINK', re.IGNORECASE),

    # Camera/dashcam/DVR
    re.compile(r'(?i)^(70mai_|ezviz_|action cam[- ]|car_cam_|car[- ]cam)'),

    # Hotel/venue
    re.compile(r'(?i)^(hotel[ -]|albergo[ -]|b&b[ -]|hostel[ -]|residence[ -]|guest[ -]|ospiti[ -]|airport[ -])'),

    # $HEX[...] encoded
    re.compile(r'^\$HEX\['),

    # IP addresses as SSID
    re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),

    # Repeated digits (3+ same digit)
    re.compile(r'^(\d)\1{2,}$'),
    # Sequential digits
    re.compile(r'^(?:0123|1234|2345|3456|4567|5678|6789|7890|9876|8765|7654|6543|5432|4321|3210)$'),

    # URLs
    re.compile(r'(?i)^https?://'),

    # Repeated symbols
    re.compile(r'^[^a-zA-Z0-9]{1,10}$'),
    re.compile(r'^[^a-zA-Z0-9]{1,3}$'),
]

def is_trash(essid: str) -> bool:
    stripped = essid.strip()
    if not stripped:
        return True
    if len(stripped) <= 4 and not re.search(r'[a-zA-Z]{2,}', stripped):
        return True
    for pattern in TRASH_PATTERNS:
        if pattern.search(stripped):
            return True
    return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python split_essids.py <input_file> [trash_output] [usable_output]")
        sys.exit(1)

    input_path = sys.argv[1]
    trash_path = sys.argv[2] if len(sys.argv) > 2 else "trash.txt"
    usable_path = sys.argv[3] if len(sys.argv) > 3 else "usable.txt"

    trash_count = 0
    usable_count = 0

    with open(input_path, 'r', encoding='utf-8', errors='replace') as fin, \
         open(trash_path, 'w', encoding='utf-8') as ftrash, \
         open(usable_path, 'w', encoding='utf-8') as fuse:

        for line in fin:
            essid = line.rstrip('\n\r')
            if is_trash(essid):
                ftrash.write(line)
                trash_count += 1
            else:
                fuse.write(line)
                usable_count += 1

    print(f"Done. Trash: {trash_count}, Usable: {usable_count}")
    print(f"Trash output: {trash_path}")
    print(f"Usable output: {usable_path}")

if __name__ == "__main__":
    main()
