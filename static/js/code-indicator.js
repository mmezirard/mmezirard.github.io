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
    php: "PHP",
    plain: "PLAINTEXT",
    ps1: "POWERSHELL",
    py: "PYTHON",
    sh: "SHELL",
    xml: "XML",
}
