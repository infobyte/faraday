The **RELEASE.md** generation process is as follows:

 * An _CHANGELOG_ folder, containing files for the wanted generated **RELEASE.md** (release file upon now)
 * As root of this folder, we have:
    * A folder **for each** version, each one containing various (0 to multiple) .md one line file, explaining a single change released in the proper version
        * The version folder can contains a _date.md_ file, which contains the realease date
        * The only reserved file names are _white.md, pink.md, black.md_ and _date.md_
        * Any other file not ending in .md will be ignored
    * _header.md_, md format lines at the beginning of the release file
    * _footer.md_, md format lines at the ending of the release file
    * _changelog.py_, a python file, which will generate the release file
 * The python file process is:
    * Iterate over all the version folder in sorted order, joining all .json files in only one .md (
      _community/prof/corp.md_ ) in the proper version folder.
    * Generate the release file as header/v0file.md/.../vnfile.md/footer
 * The release step-by-step generation should be:
    1. Checkout white/master and go to CHANGELOG/
    1. Run _changelog.py_ (All .md file will be compressed to _white.md_ files, excluding reserved filenames files)
    1. Replace _old **RELEASE.md**_ with new generated file
    1. Git add CHANGELOG/
    1. Commit & push
    1. Checkout pink/master and go to CHANGELOG/
    1. Merge white/master
    1. Run _changelog.py_ (All .md file will be compressed to _pink.md_ files, excluding reserved filenames files)
    1. Replace _old **RELEASE.md**_ with new generated file
    1. Git add CHANGELOG/
    1. Commit & push
    1. Checkout black/master and go to CHANGELOG/
    1. Merge pink/master
    1. Run _changelog.py_ (All .md file will be compressed to _black.md_ files, excluding reserved filenames files)
    1. Replace _old **RELEASE.md**_ with new generated file
    1. Git add CHANGELOG/
    1. Commit & push

As for faraday 3.15.0, the changelog file changed to .json format with this structure:
```json
{
  "level": "community|prof|corp",
  "md": "<changelog text>"
}
```
