document.addEventListener("DOMContentLoaded", function () {
    const preElements = document.querySelectorAll("pre")

    preElements.forEach(function (preElement) {
        const divElement = document.createElement("div")
        divElement.className = "code-wrapper"

        preElement.parentNode.insertBefore(divElement, preElement)
        divElement.appendChild(preElement.cloneNode(true))
        preElement.parentNode.removeChild(preElement)
    })
})
