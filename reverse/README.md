# Configure for GitHub wiki (reverse)

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

## Usage

![GitHub Actions](https://img.shields.io/static/v1?style=for-the-badge&message=GitHub+Actions&color=2088FF&logo=GitHub+Actions&logoColor=FFFFFF&label=)
![GitHub](https://img.shields.io/static/v1?style=for-the-badge&message=GitHub&color=181717&logo=GitHub&logoColor=FFFFFF&label=)

⚠️ This is only useful in a very specific scenario: un-wiki-ifying links so that
they work in the normal GitHub source viewer. This is only useful if you're
downloading published wiki content and committing it to your source repository.

```yml
# .github/workflows/download-wiki.yml
name: download-wiki
on:
  gollum:
  schedule:
    - cron: "8 14 * * *"
jobs:
  download-wiki:
    if: github.event_name != 'push'
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: rm -rf wiki
      - uses: actions4gh/download-wiki@v1
        with:
          path: wiki
      - uses: actions4gh/configure-wiki/reverse@v1
      - uses: stefanzweifel/git-auto-commit-action@v5
```

👆 This GitHub workflow will download the content from the GitHub wiki tab and
un-wiki-ify the links before pushing the result to the source repository.

### Bidirectional wiki sync

Sometimes you want two-way wiki sync so that edits from the repository are
reflected in the wiki and edits from the wiki are committed to the repository.
You've seen above how to go from the source repository to the wiki tab. Here's a
complete demo using [actions4gh/deploy-wiki] to push the content to the wiki and
[actions4gh/download-wiki] to perform the reverse of downloading the wiki
content and commiting it to the source repository.

```yml
# .github/workflows/sync-wiki.yml
name: Sync wiki
on:
  push:
    branches: "main"
    paths: wiki/**
  gollum:
  schedule:
    - cron: "8 14 * * *"
jobs:
  deploy-wiki:
    if: github.event_name == 'push'
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions4gh/configure-wiki@v1
      - uses: actions4gh/deploy-wiki@v1
  download-wiki:
    if: github.event_name != 'push'
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: rm -rf wiki
      - uses: actions4gh/download-wiki@v1
        with:
          path: wiki
      - uses: actions4gh/configure-wiki/reverse@v1
      - uses: stefanzweifel/git-auto-commit-action@v5
```
