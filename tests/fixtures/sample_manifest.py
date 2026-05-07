{
    "name": "Test Module",
    "version": "1.0.0",
    "depends": ["base", "web"],
    "data": ["security/ir.model.access.csv", "views/templates.xml"],
    "demo": ["demo/demo_data.xml"],
    "external_dependencies": {"python": ["requests", "cryptography"]},
    "installable": true,
    "application": false,
    "license": "LGPL-3"
}
