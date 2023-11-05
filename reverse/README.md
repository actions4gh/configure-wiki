# Configure GitHub wiki (reverse)

📄 Transform `./My-page` wiki links into `./My-page.md` source links

<table align=center><td>

```md
<!-- Home.md input -->
[Other page](./Other-page)
```

<td>

```md
<!-- README.md result -->
[Other page](./Other-page.md)
```

</table>

🔗 Properly rewrites extensionless links to work in GitHub's source viewer \
📛 Also renames `Home.md` to `README.md`

🔁 See also [actions4gh/configure-wiki] which is the inverse of this action. It
converts source-style links to wiki-style.

## Usage

![GitHub Actions](https://img.shields.io/static/v1?style=for-the-badge&message=GitHub+Actions&color=2088FF&logo=GitHub+Actions&logoColor=FFFFFF&label=)
![GitHub](https://img.shields.io/static/v1?style=for-the-badge&message=GitHub&color=181717&logo=GitHub&logoColor=FFFFFF&label=)

⚠️ This is only useful downloading published wiki content and committing it to
your source repository.

```yml
# .github/workflows/commit-wiki.yml
name: commit-wiki
on:
  gollum:
  schedule:
    - cron: "8 14 * * *"
jobs:
  commit-wiki:
    if: github.event_name != 'push'
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.repository }}.wiki
          path: wiki
      - run: rm -rf wiki/.git
      - uses: actions4gh/configure-wiki/reverse@v1
      - uses: stefanzweifel/git-auto-commit-action@v5
```

👆 This GitHub workflow will download the content from the GitHub wiki tab and
un-wiki-ify the links before pushing the result to the source repository.

### Inputs

- **`path`:** Where the wiki files are. This must be a folder. Defaults to
  `wiki/`. All files one level deep (not recursively) in this folder will be
  processed.
