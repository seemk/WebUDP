{
  "targets": [
    {
      "target_name": "WebUDP",
      "sources": ["WuHostNode.cpp"],
      "link_settings": {
        "libraries": ["-lWu"]
      },
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
