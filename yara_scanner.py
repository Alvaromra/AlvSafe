import yara

rules = yara.compile(
    filepath='yara_rules/malware_rules.yar'
)


def yara_scan(file_path):

    try:

        matches = rules.match(file_path)

        return matches

    except:
        return []