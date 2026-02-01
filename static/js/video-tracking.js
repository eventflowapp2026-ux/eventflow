// static/js/video-tracking.js
document.addEventListener('DOMContentLoaded', function() {
    const videos = document.querySelectorAll('video');
    
    videos.forEach(video => {
        // Add progress tracking
        video.addEventListener('timeupdate', function() {
            const progress = (this.currentTime / this.duration) * 100;
            trackVideoProgress(progress);
        });
        
        // Mark as completed
        video.addEventListener('ended', function() {
            markVideoAsWatched();
        });
        
        // Add progress bar if not present
        addProgressBar(video);
    });
    
    function trackVideoProgress(progress) {
        // Log to console (replace with your analytics)
        console.log(`Video progress: ${progress.toFixed(2)}%`);
        
        // Update progress bar if exists
        const progressBar = document.querySelector('.video-progress-bar-fill');
        if (progressBar) {
            progressBar.style.width = `${progress}%`;
        }
        
        // Save to localStorage at milestones
        if (progress >= 25 && progress < 26) localStorage.setItem('video_25', 'true');
        if (progress >= 50 && progress < 51) localStorage.setItem('video_50', 'true');
        if (progress >= 75 && progress < 76) localStorage.setItem('video_75', 'true');
    }
    
    function markVideoAsWatched() {
        // Get current step from page
        const step = getCurrentStep();
        if (step) {
            localStorage.setItem(`video_step_${step}_watched`, 'true');
            localStorage.setItem(`video_step_${step}_watched_at`, new Date().toISOString());
            
            // Show completion message
            showCompletionMessage();
        }
    }
    
    function getCurrentStep() {
        // Try to get step from URL
        const path = window.location.pathname;
        const stepMatch = path.match(/step\/(\d+)/);
        if (stepMatch) return stepMatch[1];
        
        // Try to get from data attribute
        const stepElement = document.querySelector('[data-step]');
        if (stepElement) return stepElement.dataset.step;
        
        return null;
    }
    
    function showCompletionMessage() {
        if (document.querySelector('.video-completion-alert')) return;
        
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-success alert-dismissible fade show mt-3 video-completion-alert';
        alertDiv.innerHTML = `
            <i class="bi bi-check-circle me-2"></i>
            <strong>Great job!</strong> You've completed this tutorial.
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        const videoContainer = document.querySelector('.video-container');
        if (videoContainer) {
            videoContainer.parentNode.insertBefore(alertDiv, videoContainer.nextSibling);
        }
    }
    
    function addProgressBar(video) {
        if (document.querySelector('.video-progress-container')) return;
        
        const container = document.createElement('div');
        container.className = 'video-progress-container mt-2';
        container.innerHTML = `
            <div class="d-flex justify-content-between align-items-center small text-muted mb-1">
                <span>Progress</span>
                <span class="video-progress-text">0%</span>
            </div>
            <div class="progress" style="height: 4px;">
                <div class="progress-bar video-progress-bar-fill" role="progressbar" style="width: 0%"></div>
            </div>
        `;
        
        video.parentNode.insertBefore(container, video.nextSibling);
        
        // Update progress text
        video.addEventListener('timeupdate', function() {
            const progress = (this.currentTime / this.duration) * 100;
            const progressText = document.querySelector('.video-progress-text');
            if (progressText) {
                progressText.textContent = `${progress.toFixed(0)}%`;
            }
        });
    }
});
