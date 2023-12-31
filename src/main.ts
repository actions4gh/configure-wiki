import process from "node:process";
import { readFile, writeFile, readdir, rename } from "node:fs/promises";
import * as core from "@actions/core";
import { remark } from "remark";
import { visit } from "unist-util-visit";
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
