document.addEventListener('DOMContentLoaded', function () {
    const codeWrapperElements = document.querySelectorAll('.code-wrapper')

    codeWrapperElements.forEach(function (codeWrapperElement) {
        const preElement = codeWrapperElement.querySelector('pre')

        const codeIndicator = document.createElement('div')
        codeIndicator.className = 'code-indicator'

        let langCode = preElement.dataset.lang

        if (langCode === undefined) {
            langCode = 'plain'
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
    'c#': 'C#',
    'cmd': 'CMD',
    'css': 'CSS',
    'html': 'HTML',
    'json': 'JSON',
    'lua': 'LUA',
    'php': 'PHP',
    'pl': 'PERL',
    'plain': 'PLAINTEXT',
    'py': 'PYTHON',
    'sh': 'SHELL',
    'sql': 'SQL',
}
