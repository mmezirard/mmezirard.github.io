document.addEventListener("DOMContentLoaded", function () {
    const codeWrapperElements = document.querySelectorAll(".code-wrapper")

    codeWrapperElements.forEach(function (codeWrapperElement) {
        const preElement = codeWrapperElement.querySelector("pre")

        const codeIndicator = document.createElement("div")
        codeIndicator.className = "code-indicator"

        let langCode = preElement.dataset.lang

        if (langCode === undefined) {
            langCode = "plain"
        }

        codeIndicator.dataset.lang = langCode
        codeIndicator.textContent = languageMapping[langCode]

        codeWrapperElement.insertBefore(
            codeIndicator,
            codeWrapperElement.firstChild
        )
    })
})

const languageMapping = {
    bat: "CMD",
    c: "C",
    "c#": "C#",
    html: "HTML",
    java: "JAVA",
    js: "JAVASCRIPT",
    json: "JSON",
    php: "PHP",
    pl: "PERL",
    plain: "PLAINTEXT",
    ps1: "POWERSHELL",
    py: "PYTHON",
    rb: "RUBY",
    sh: "SHELL",
    sql: "SQL",
    tex: "LATEX",
    xml: "XML",
    yml: "YAML",
}
