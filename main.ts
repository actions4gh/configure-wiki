// 2>/dev/null; v=1.38.0; [ -d "${i="$RUNNER_TOOL_CACHE/deno/$v/$(echo "$RUNNER_ARCH" | tr '[:upper:]' '[:lower:]')"}" ] || curl -fsSL https://deno.land/x/install/install.sh |DENO_INSTALL="$i" sh -s "v$v" &>/dev/null; exec "$i/bin/deno" run -Aq "$0" "$@"
import process from "node:process";
import { readFile, writeFile, readdir, rename } from "node:fs/promises";
import * as core from "npm:@actions/core@^1.10.0";
import { remark } from "npm:remark@^14.0.3";
import { visit } from "npm:unist-util-visit@^5.0.0";
import { resolve, extname, parse } from "node:path";
import { fileURLToPath } from "node:url";

const markdownExtensions = [
  "md",
  "markdown",
  "mdown",
  "mkdn",
  "mkd",
  "mdwn",
  "mkdown",
  "ron",
];

const plugin = () => (tree: any) => {
  visit(tree, ["link", "linkReference"], (node: any) => {
    const fakeURL = new URL(node.url, "file:///Z:/-/");
    const { ext, name } = parse(fileURLToPath(fakeURL));

    if (!markdownExtensions.includes(ext.slice(1))) {
      console.log(`${node.url} is not a Markdown link`);
      return;
    }
    if (!fakeURL.href.startsWith("file:///Z:/-/")) {
      console.log(`${node.url} is not a local "./"-like link`);
    }

    const oldNodeURL = node.url;
    if (name.toLowerCase() === "readme") {
      node.url = "Home" + fakeURL.search + fakeURL.hash;
    } else {
      node.url = name + fakeURL.search + fakeURL.hash;
    }
    console.log(`Rewrote ${oldNodeURL} to ${node.url}`);
  });
};

for (const file of await readdir(core.getInput("path"))) {
  const path = resolve(core.getInput("path"), file);
  const extension = extname(path);
  const { name } = parse(path);

  if (!markdownExtensions.includes(extension.slice(1))) {
    console.log(`${path} is not a Markdown file`);
    continue;
  }

  console.log(`Processing ${path}`);
  let md = await readFile(path, "utf-8");
  md = (await remark().use(plugin).process(md)).toString();
  await writeFile(path, md);

  if (name.toLowerCase() === "readme") {
    await rename(path, resolve(path, "../Home.md"));
  }
}

core.setOutput(
  "base-url",
  `${process.env.GITHUB_SERVER}/${process.env.GITHUB_REPOSITORY}/wiki/`
);
