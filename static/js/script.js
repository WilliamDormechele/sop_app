// static/script.js

// 🔐 Confirm delete popup
function confirmDelete(fileName) {
  return confirm(`Are you sure you want to delete "${fileName}"?`);
}

// 📋 Load and refresh 'My Actions'
function loadMyActions() {
  fetch("/my_actions")
    .then(response => response.json())
    .then(data => {
      const container = document.getElementById("my-actions-container");
      container.innerHTML = "";

      if (data.length === 0) {
        container.innerHTML = '<div class="no-action">No Outstanding Actions</div>';
      } else {
        data.forEach(sop => {
          container.innerHTML += `
            <div class="action-item">
              <a href="/sops#sop-${sop.id}">${sop.title}</a>
            </div>`;
        });
      }
    });
}

// 🚀 Run once the DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  loadMyActions();  // auto-load on page open

  const refreshBtn = document.getElementById("refresh-actions");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", loadMyActions);
  }
});
