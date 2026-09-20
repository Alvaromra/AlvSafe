# ============================================
# engine/heuristic.py
# ============================================

suspicious_keywords = [

    'powershell -enc',

    'cmd.exe /c',

    'wget',

    'curl',

    'base64',

    'CreateRemoteThread',

    'VirtualAlloc',

    'WriteProcessMemory',

    'Invoke-Expression',

    'DownloadString',

    'mimikatz',

    'nc.exe',

    'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'
]

# ============================================
# HEURISTIC
# ============================================

def heuristic_scan(file_path):

    try:

        with open(
            file_path,
            'rb'
        ) as f:

            content = f.read()

        # ====================================
        # UTF-16 FIX
        # ====================================

        try:

            decoded = content.decode(
                'utf-8',
                errors='ignore'
            )

        except:

            decoded = ''

        try:

            decoded_utf16 = content.decode(
                'utf-16',
                errors='ignore'
            )

        except:

            decoded_utf16 = ''

        full_content = (
            decoded +
            decoded_utf16
        ).lower()

        for keyword in suspicious_keywords:

            if keyword.lower() in full_content:

                print(
                    f'[HEURISTIC] '
                    f'{keyword}'
                )

                return True

    except Exception as e:

        print(
            f'[HEURISTIC ERROR] '
            f'{e}'
        )

    return False