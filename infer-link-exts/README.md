## Usage

Rewrites this:

```md
- [Hello world](./Hello-world)
- [Home with #](./Home#hello)
- [README with ?](./README?hello)
```

...to this:

```md
- [Hello world](Hello-world.md)
- [Home with #](Home.md#hello)
- [README with ?](README.md?hello)
```

That way you can use the same links that work in your GitHub source control on
the GitHub wiki!

```yml
- uses: jcbhmr/preprocess-github-wiki-for-source
  with:
    path: wiki
```
