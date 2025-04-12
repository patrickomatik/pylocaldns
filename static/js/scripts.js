// Mobile navigation toggle
document.addEventListener('DOMContentLoaded', function() {
    const navToggle = document.querySelector('.nav-toggle');
    if (navToggle) {
        navToggle.addEventListener('click', function() {
            document.querySelector('.nav-links').classList.toggle('active');
        });
    }
    
    // Set up confirmation dialogs for delete operations
    const deleteButtons = document.querySelectorAll('[data-confirm]');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            const message = this.getAttribute('data-confirm');
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });
});

// Confirmation dialogs
function confirmDelete(mac) {
    return confirm('Are you sure you want to delete the entry for MAC: ' + mac + '?');
}

// Function to refresh the dashboard content
function refreshDashboard() {
    if (typeof htmx !== 'undefined') {
        htmx.trigger('#dashboard-content', 'refresh');
    }
}

// Function to show a loading indicator
function showLoading(id) {
    const element = document.getElementById(id);
    if (element) {
        element.innerHTML = '<div class="spinner"></div> Loading...';
    }
}

// Function to hide a loading indicator
function hideLoading(id) {
    const element = document.getElementById(id);
    if (element) {
        element.innerHTML = '';
    }
}
