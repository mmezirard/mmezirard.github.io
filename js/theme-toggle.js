function setTheme(mode) {
    localStorage.setItem('theme', mode)
    const htmlElement = document.querySelector('html')

    if (mode == 'light') {
        document.getElementById('theme-toggle-sun').style.display = 'none'
        document.getElementById('theme-light-style').disabled = false
        document.getElementById('theme-toggle-moon').style.display =
            'inline-block'
        document.getElementById('theme-dark-style').disabled = true
        htmlElement.classList.remove('dark')
        htmlElement.classList.add('light')
    } else if (mode == 'dark') {
        document.getElementById('theme-toggle-sun').style.display =
            'inline-block'
        document.getElementById('theme-light-style').disabled = true
        document.getElementById('theme-toggle-moon').style.display = 'none'
        document.getElementById('theme-dark-style').disabled = false
        htmlElement.classList.remove('light')
        htmlElement.classList.add('dark')
    }
}

function toggleTheme() {
    if (localStorage.getItem('theme') === 'light') {
        setTheme('dark')
    } else if (localStorage.getItem('theme') === 'dark') {
        setTheme('light')
    }
}

function getSavedTheme() {
    let currentTheme = localStorage.getItem('theme')
    if (!currentTheme) {
        if (
            window.matchMedia &&
            window.matchMedia('(prefers-color-scheme: dark)').matches
        ) {
            currentTheme = 'dark'
        } else {
            currentTheme = 'light'
        }
    }

    return currentTheme
}

setTheme(getSavedTheme())
