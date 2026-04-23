// Smooth scroll functionality for navigation links
const scrollLinks = document.querySelectorAll('a[href^="#"]');

scrollLinks.forEach(link => {
    link.addEventListener('click', function(e) {
        e.preventDefault();

        const targetId = this.getAttribute('href');
        const targetSection = document.querySelector(targetId);

        // Smooth scroll to the section
        targetSection.scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// Click handler for CTA button
const ctaButton = document.getElementById('cta-button');

if (ctaButton) {
    ctaButton.addEventListener('click', function() {
        // Add your click handling functionality here
        alert('CTA button clicked!');
    });
}