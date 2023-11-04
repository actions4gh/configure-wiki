# Configure for GitHub wiki

📄 Transform `./My-page.md` source links into `./My-page` wiki links

<table align=center><td>

```md
<!-- README.md input -->

[Other page](./Other-page.md)
```

<td>

```md
<!-- Home.md result -->

[Other page](./Other-page)
```

</table>

🔗 Properly rewrites links to work when deployed to the wiki tab \
📛 Also renames `README.md` to `Home.md`

🔁 See also [actions4gh/configure-wiki/reverse] which is the inverse of this
action. It converts wiki-style links to source-style.

## Usage

![GitHub Actions](https://img.shields.io/static/v1?style=for-the-badge&message=GitHub+Actions&color=2088FF&logo=GitHub+Actions&logoColor=FFFFFF&label=)
![GitHub](https://img.shields.io/static/v1?style=for-the-badge&message=GitHub&color=181717&logo=GitHub&logoColor=FFFFFF&label=)

**🚀 Here's what you're after:**

```yml
# .github/workflows/deploy-wiki.yml
name: deploy-wiki
on:
  push:
    branches: "main"
    paths: wiki/**
jobs:
  deploy-wiki:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions4gh/configure-wiki@v1
      - uses: actions4gh/deploy-wiki@v1
```

👀 Check out [actions4gh/deploy-wiki]!

⚠️ Currently this Action only processes Markdown links in Markdown files. In the
future AsciiDoc and other formats may be supported.

### Inputs

- **`path`:** Where the wiki files are. This must be a folder. Defaults to
  `wiki/`. All files one level deep (not recursively) in this folder will be
  processed.

### Outputs

- **`base-url`:** The base URL of the wiki. Usually this is something like
  `https://github.com/octocat/project/wiki/`.

[actions4gh/deploy-wiki]: https://github.com/actions4gh/deploy-wiki
[actions4gh/configure-wiki/reverse]: https://github.com/actions4gh/configure-wiki/tree/main/reverse
