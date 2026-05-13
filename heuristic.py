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
    'nc.exe'
]


def heuristic_scan(file_path):

    try:

        with open(
            file_path,
            'r',
            errors='ignore'
        ) as f:

            content = f.read()

            for keyword in suspicious_keywords:

                if keyword.lower() in content.lower():

                    return True

    except:
        pass

    return False