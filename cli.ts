#!/usr/bin/env -S deno run -Aq
import process from "node:process";
import { readFile, writeFile, readdir, rename } from "node:fs/promises";
import * as core from "npm:@actions/core@^1.10.0";
import { remark } from "npm:remark@^14.0.3";
import { visit } from "npm:unist-util-visit@^5.0.0";

const mdRe = /\.(?:md|markdown|mdown|mkdn|mkd|mdwn|mkdown|ron)$/;
const plugin = () => (tree: any) =>
  visit(tree, ["link", "linkReference"], (node: any) => {
    const x = node.url;

    const fakeURL = new URL(node.url, "file:///-/");
    if (!mdRe.test(fakeURL.pathname)) {
      console.log(`${node.url} is not a Markdown file`);
      return;
    }
    if (!fakeURL.href.startsWith("file:///-/")) {
      console.log(`${node.url} is not "./"-like`);
      return;
    }

    node.url = node.url.replace(mdRe, "");
    const fakeURL2 = new URL(node.url, "file:///-/");
    if (fakeURL2.href === "file:///-/README") {
      node.url = "Home";
    }

    console.log(`Rewrote ${x} to ${node.url}`);
  });
for (const file of await readdir(core.getInput("path"))) {
  if (!mdRe.test(file)) {
    continue;
  }

  let md = await readFile(file, "utf-8");
  md = (await remark().use(plugin).process(md)).toString();
  await writeFile(file, md);

  if (file.slice(0, mdRe.exec(file)!.index) === "README") {
    await rename(file, "Home.md");
    console.log(`Renamed ${file} to Home.md`);
  }
}
