# Configure for GitHub wiki (reverse)

📄 Transform `./My-page` wiki links into `./My-page.md` source links

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

🔁 See also [actions4gh/configure-wiki/reverse] which is the inverse of this action. It converts wiki-style links to source-style.

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

[actions4gh/deploy-wiki]: https://github.com/actions4gh/deploy-wiki
