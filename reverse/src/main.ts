import { existsSync } from "node:fs";
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

function getBestMarkdownFileName(name: string, baseDir: string): string {
  for (const markdownExtension of markdownExtensions) {
    if (existsSync(resolve(baseDir, name + "." + markdownExtension))) {
      return name + "." + markdownExtension;
    }
  }
  return name + ".md";
}

const plugin = () => (tree: any) => {
  visit(tree, ["link", "linkReference"], (node: any) => {
    const fakeURL = new URL(node.url, "file:///Z:/-/");
    const { ext, name } = parse(fileURLToPath(fakeURL));

    if (ext) {
      console.log(`${node.url} is not a bare link`);
      return;
    }
    if (!fakeURL.href.startsWith("file:///Z:/-/")) {
      console.log(`${node.url} is not a local "./"-like link`);
      return;
    }

    const oldNodeURL = node.url;
    if (name.toLowerCase() === "home") {
      node.url = "README.md" + fakeURL.search + fakeURL.hash;
    } else {
      // ex: "Hello-world" => "Hello-world.markdown"
      const bestFileName = getBestMarkdownFileName(
        name,
        resolve(core.getInput("path"))
      );
      node.url = bestFileName + fakeURL.search + fakeURL.hash;
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

  if (name.toLowerCase() === "home") {
    await rename(path, resolve(path, "../README.md"));
    console.log(`Renamed ${path} to README.md`);
  }
}
