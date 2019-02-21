import os
import packaging.version

LEVEL = "white"

def match(elem):
    try:
        ans = packaging.version.Version(elem)
    except packaging.version.InvalidVersion as e:
        # print folder/file ommited
        return False
    return ans

IGNORED_FILES = ["white.md", "pink.md", "black.md", "date.md"]

def addFile(filename,changelog_file,to=None):
    with open(filename, "r") as date_file:
        if to:
            changelog_file.write(date_file.readline()[:to])
        else:
            changelog_file.writelines(date_file.readlines())

def main(level):

    ls_ans = os.listdir(".")
    folders = list(sorted(filter(lambda el: el, map(lambda elem: match(elem),ls_ans)),reverse=True))
    with open("RELEASE.md","w") as changelog_file:
        if "header.md" in ls_ans:
            with open("header.md", "r") as header_file:
                changelog_file.writelines(header_file.readlines())
                changelog_file.writelines("\n\n")
        for folder in folders:
            changelog_file.write(str(folder))
            inner_files = list(filter(lambda elem: elem.endswith(".md") ,os.listdir("./" + str(folder))))
            if "date.md" in inner_files:
                changelog_file.write(" [")
                addFile("./" + str(folder) + "/date.md",changelog_file,-1)
                changelog_file.write("]")
            changelog_file.writelines(":\n---\n")
            if level != "white":
                addFile("./" + str(folder) + "/white.md",changelog_file)
            if level == "black":
                addFile("./" + str(folder) + "/pink.md",changelog_file)
            level_filename = "./" + str(folder) + "/" + level + ".md"

            previous = [""]
            if level + ".md" in os.listdir("./" + str(folder)):
                with open(level_filename, "r") as level_file:
                    previous = level_file.readlines()

            with open(level_filename, "w") as level_file:
                level_file.writelines(previous)
                for inner_file_name in inner_files:
                    if inner_file_name not in IGNORED_FILES:
                        level_file.write(" * ")
                        addFile("./" + str(folder) + "/" + inner_file_name, level_file)
                        level_file.write("\n")
                        os.remove("./" + str(folder) + "/" + inner_file_name)
            addFile(level_filename, changelog_file)
            changelog_file.writelines("\n")

        if "footer.md" in ls_ans:
            with open("footer.md", "r") as footer_file:
                changelog_file.writelines(footer_file.readlines())


if __name__ == '__main__':
    level = LEVEL # if not level_passed else level_pased
    main(level)

