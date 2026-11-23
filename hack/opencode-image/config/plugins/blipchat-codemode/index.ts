// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { Plugin } from "@opencode/plugin"

export default Plugin.define({
  id: "blipchat.codemode",
  async setup(ctx) {
    await ctx.mcp.transform((editor) => {
      if (!editor.get("blipchat")) return
      editor.update("blipchat", (server) => {
        server.codemode = false
      })
    })
  },
})
