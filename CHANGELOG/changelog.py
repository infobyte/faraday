import json
from pathlib import Path
from typing import Dict

import packaging.version

LEVEL = "community"
LEVELS = ["community", "prof", "corp"] if LEVEL == "corp" else ["community"]
MD_FILES = ["community.md", "prof.md", "corp.md", "date.md"] if LEVEL == "corp" else ["community.md", "date.md"]


def match(elem: str):
    try:
        ans = packaging.version.Version(elem)
    except packaging.version.InvalidVersion as e:
        # print folder/file ommited
        return False
    return ans


def add_md_file(filename, changelog_file):
    with filename.open("r") as date_file:
        changelog_file.write(date_file.readline()[:-1])


def get_md_text_from_json_file(filepath: Path, level_dict):
    with filepath.open("r") as file:
        file_json: Dict = json.loads(file.read())
        level = file_json.get("level")
        level_dict[level] += f" * {file_json.get('md')}\n"


def main():
    ls_ans = [path.name for path in Path(__file__).parent.iterdir()]
    folders = list(sorted(filter(lambda el: el, map(lambda elem: match(elem), ls_ans)), reverse=True))
    with (Path(__file__).parent / "RELEASE.md").open("w") as changelog_file:
        if "header.md" in ls_ans:
            with (Path(__file__).parent / "header.md").open("r") as header_file:
                changelog_file.writelines(header_file.readlines())
                changelog_file.writelines("\n\n")
        for folder in folders:
            changelog_file.write(str(folder))
            inner_files = list(filter(lambda elem: elem.suffix == ".json" or elem.name in MD_FILES,
                                      (Path(__file__).parent / str(folder)).iterdir()))
            if any([file.name == "date.md" for file in inner_files]):
                changelog_file.write(" [")
                add_md_file(Path(__file__).parent / str(folder) / "date.md", changelog_file)
                changelog_file.write("]")
            changelog_file.writelines(":\n---\n")

            level_dicts = {level: "" for level in LEVELS}
            for level in LEVELS:
                if any([file.name == f"{level}.md" for file in inner_files]):
                    with (Path(__file__).parent / str(folder) / f"{level}.md").open("r") as level_file:
                        level_dicts[level] = level_file.read()
            for inner_file in filter(lambda elem: elem.suffix == ".json", inner_files):
                get_md_text_from_json_file(inner_file, level_dicts)
                inner_file.unlink()
            for level in LEVELS:
                with (Path(__file__).parent / str(folder) / f"{level}.md").open("w") as level_file:
                    level_file.write(level_dicts[level])
                changelog_file.write(level_dicts[level])
            changelog_file.writelines("\n")

        if "footer.md" in ls_ans:
            with (Path(__file__).parent / "footer.md").open("r") as footer_file:
                changelog_file.writelines(footer_file.readlines())


if __name__ == '__main__':
    main()
