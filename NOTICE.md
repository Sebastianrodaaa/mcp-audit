# Notice

`data/mcptox.jsonl` is derived from the **MCPTox benchmark** (Wang et al., *MCPTox: A Benchmark for Tool Poisoning
Attack on Real-World MCP Servers*, AAAI 2026), https://github.com/zhiqiangwang4/MCPTox-Benchmark at commit
`630121b3275f74cc72d000a7a056e4d3c68648ef`, licensed under CC BY 4.0. `eval/build_mcptox.py` reproduces the file from
that commit: it pairs the poisoned tool definitions with the clean tools of the same servers and assigns each server
to a dev or test split with a fixed seed. Changes: reformatted to JSONL, clean tools parsed out of the benchmark's
system prompts, split column added.

The scanner code is MIT licensed (see `LICENSE`).

## Art and fonts

| asset | used in | source | license |
|---|---|---|---|
| Albrecht Dürer, *Saint Michael Fighting the Dragon* (1498), National Gallery of Art 142359 | `docs/art/durer_st_michael.jpg`, banner left edge (dithered) | https://commons.wikimedia.org/wiki/File:Albrecht_D%C3%BCrer,_Saint_Michael_Fighting_the_Dragon,_1498,_NGA_142359.jpg | Public domain / CC0 (NGA Open Access) |
| Albrecht Dürer, *Saint Jerome in His Study* (1514), National Gallery of Art 35095 | `docs/art/durer_st_jerome.jpg`, banner right edge (dithered) | https://commons.wikimedia.org/wiki/File:Albrecht_D%C3%BCrer,_Saint_Jerome_in_His_Study,_1514,_NGA_35095.jpg | Public domain / CC0 (NGA Open Access) |
| UnifrakturMaguntia (banner title, rendered as a bitmap) | `docs/art/UnifrakturMaguntia-Book.ttf` | https://github.com/google/fonts/tree/main/ofl/unifrakturmaguntia | SIL Open Font License 1.1 |
| DejaVu Sans Mono (banner tagline, GIF text) | system font, not shipped | https://dejavu-fonts.github.io | Bitstream Vera / DejaVu license |
