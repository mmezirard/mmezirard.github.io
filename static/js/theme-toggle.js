document.addEventListener("DOMContentLoaded", function () {
    setTheme(getSavedTheme())
})

function setTheme(mode) {
    localStorage.setItem("theme", mode)

    const htmlElement = document.querySelector("html")
    const toggleSun = document.getElementById("theme-toggle-sun")
    const toggleMoon = document.getElementById("theme-toggle-moon")
    const styleLight = document.getElementById("theme-light-style")
    const styleDark = document.getElementById("theme-dark-style")

    if (mode == "light") {
        toggleSun.style.display = "none"
        styleLight.disabled = false
        toggleMoon.style.display = "inline-block"
        styleDark.disabled = true
        htmlElement.classList.remove("dark")
        htmlElement.classList.add("light")
    } else if (mode == "dark") {
        toggleSun.style.display = "inline-block"
        styleLight.disabled = true
        toggleMoon.style.display = "none"
        styleDark.disabled = false
        htmlElement.classList.remove("light")
        htmlElement.classList.add("dark")
    }
}

function toggleTheme() {
    if (localStorage.getItem("theme") === "light") {
        setTheme("dark")
    } else if (localStorage.getItem("theme") === "dark") {
        setTheme("light")
    }
}

function getSavedTheme() {
    let currentTheme = localStorage.getItem("theme")
    if (!currentTheme) {
        if (
            window.matchMedia &&
            window.matchMedia("(prefers-color-scheme: dark)").matches
        ) {
            currentTheme = "dark"
        } else {
            currentTheme = "light"
        }
    }

    return currentTheme
}
