/*/ 2> /dev/null
set -e
deno_version='1.38.0'
case $RUNNER_ARCH in
  X86) arch=ia32 ;;
  X64) arch=x64 ;;
  ARM) arch=arm ;;
  ARM64) arch=arm64 ;;
esac
deno_install="$RUNNER_TOOL_CACHE/deno/$version/$arch"
if [ ! -d "$deno_install" ]; then
  if ! o=$(curl -fsSL https://deno.land/x/install/install.sh | DENO_INSTALL="$deno_install" sh -s "v$deno_version" 2>&1); then
    echo "$o" >&2
    exit 1
  fi
fi
exec "$deno_install/bin/deno" run -Aq "$0" "$@"
# */

import process from "node:process";
import { existsSync } from "node:fs";
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
}

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
