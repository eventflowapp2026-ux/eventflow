# video_manager.py
"""
Video management for How It Works guide
Handles video uploads, thumbnails, and metadata
"""

import os
from werkzeug.utils import secure_filename
from flask import url_for

class VideoManager:
    def __init__(self, upload_folder='static/videos/how-it-works'):
        self.upload_folder = upload_folder
        self.thumbnails_folder = 'static/videos/thumbnails'
        self.allowed_extensions = {'mp4', 'webm', 'ogg', 'mov'}
        
        # Create directories if they don't exist
        os.makedirs(self.upload_folder, exist_ok=True)
        os.makedirs(self.thumbnails_folder, exist_ok=True)
    
    def allowed_file(self, filename):
        """Check if file extension is allowed"""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in self.allowed_extensions
    
    def get_video_path(self, step, filename=None):
        """Get path for step video"""
        if filename:
            return os.path.join(self.upload_folder, filename)
        # Default naming convention
        default_name = f"step{step}.mp4"
        return os.path.join(self.upload_folder, default_name)
    
    def get_thumbnail_path(self, step, filename=None):
        """Get path for step thumbnail"""
        if filename:
            return os.path.join(self.thumbnails_folder, filename)
        # Default naming convention
        default_name = f"step{step}.jpg"
        return os.path.join(self.thumbnails_folder, default_name)
    
    def upload_video(self, step, video_file, thumbnail_file=None):
        """Upload video and thumbnail for a step"""
        results = {
            'success': False,
            'video_path': None,
            'thumbnail_path': None,
            'errors': []
        }
        
        # Check if video file is valid
        if not video_file or video_file.filename == '':
            results['errors'].append('No video file selected')
            return results
        
        if not self.allowed_file(video_file.filename):
            results['errors'].append(f'File type not allowed. Allowed types: {", ".join(self.allowed_extensions)}')
            return results
        
        # Save video file
        video_filename = secure_filename(f"step{step}_{video_file.filename}")
        video_path = self.get_video_path(step, video_filename)
        
        try:
            video_file.save(video_path)
            results['video_path'] = video_path
        except Exception as e:
            results['errors'].append(f'Failed to save video: {str(e)}')
            return results
        
        # Save thumbnail if provided
        if thumbnail_file and thumbnail_file.filename != '':
            # Check if it's an image
            allowed_image_ext = {'jpg', 'jpeg', 'png', 'gif'}
            thumbnail_ext = thumbnail_file.filename.rsplit('.', 1)[1].lower()
            
            if thumbnail_ext in allowed_image_ext:
                thumbnail_filename = secure_filename(f"step{step}.{thumbnail_ext}")
                thumbnail_path = self.get_thumbnail_path(step, thumbnail_filename)
                
                try:
                    thumbnail_file.save(thumbnail_path)
                    results['thumbnail_path'] = thumbnail_path
                except Exception as e:
                    results['errors'].append(f'Failed to save thumbnail: {str(e)}')
                    # Don't fail the whole upload if thumbnail fails
        
        results['success'] = True
        return results
    
    def delete_video(self, step):
        """Delete video and thumbnail for a step"""
        # Look for any video file for this step
        video_pattern = f"step{step}"
        deleted_files = []
        
        for filename in os.listdir(self.upload_folder):
            if filename.startswith(video_pattern):
                file_path = os.path.join(self.upload_folder, filename)
                try:
                    os.remove(file_path)
                    deleted_files.append(filename)
                except:
                    pass
        
        # Delete thumbnail
        thumbnail_pattern = f"step{step}."
        for filename in os.listdir(self.thumbnails_folder):
            if filename.startswith(thumbnail_pattern):
                file_path = os.path.join(self.thumbnails_folder, filename)
                try:
                    os.remove(file_path)
                    deleted_files.append(filename)
                except:
                    pass
        
        return deleted_files
    
    def get_video_info(self, step):
        """Get information about uploaded video for a step"""
        video_info = {
            'exists': False,
            'path': None,
            'url': None,
            'size': 0,
            'thumbnail': None,
            'thumbnail_url': None
        }
        
        # Find video file
        for filename in os.listdir(self.upload_folder):
            if filename.startswith(f"step{step}"):
                video_path = os.path.join(self.upload_folder, filename)
                if os.path.exists(video_path):
                    video_info['exists'] = True
                    video_info['path'] = video_path
                    video_info['url'] = f'/static/videos/how-it-works/{filename}'
                    video_info['size'] = os.path.getsize(video_path)
                    break
        
        # Find thumbnail
        for filename in os.listdir(self.thumbnails_folder):
            if filename.startswith(f"step{step}"):
                thumbnail_path = os.path.join(self.thumbnails_folder, filename)
                if os.path.exists(thumbnail_path):
                    video_info['thumbnail'] = thumbnail_path
                    video_info['thumbnail_url'] = f'/static/videos/thumbnails/{filename}'
                    break
        
        return video_info
    
    def list_all_videos(self):
        """List all uploaded videos"""
        videos = {}
        
        for step in range(1, 5):
            video_info = self.get_video_info(step)
            if video_info['exists']:
                videos[step] = video_info
        
        return videos

# Create a global instance
video_manager = VideoManager()
