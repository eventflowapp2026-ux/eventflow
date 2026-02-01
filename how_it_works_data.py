# how_it_works_data.py
"""
How It Works Step Data Configuration
This file contains all the content for the step-by-step guide.
"""

def get_step_data(step):
    """Get data for each step of how it works guide"""
    
    # Base template for all steps
    base_step = {
        'video': True,
        'video_type': 'upcoming',  # Options: 'file', 'embed', 'upcoming'
        'screenshots': [],
        'tips': []
    }
    
    steps = {
        1: {
            'title': 'Create Your Account',
            'subtitle': 'Get started in less than a minute',
            'description': 'Sign up for your free EventFlow account to begin creating amazing event registration forms.',
            'icon': '<i class="bi bi-person-plus-fill"></i>',
            'content': '''
            <h5 class="mb-3">Why Create an Account?</h5>
            <p>Creating an account gives you access to all of EventFlow\'s powerful features:</p>
            
            <div class="row mb-4">
                <div class="col-md-6">
                    <ul class="list-check">
                        <li>Unlimited event creation</li>
                        <li>Custom form builder</li>
                        <li>Email invitation system</li>
                        <li>Response analytics</li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <ul class="list-check">
                        <li>QR code generation</li>
                        <li>PDF/CSV export</li>
                        <li>File upload support</li>
                        <li>24/7 support access</li>
                    </ul>
                </div>
            </div>
            
            <h5 class="mb-3">How to Sign Up</h5>
            <div class="row">
                <div class="col-md-4 text-center mb-3">
                    <div class="bg-light rounded-circle p-3 mb-2 mx-auto" style="width: 70px; height: 70px;">
                        <i class="bi bi-person-fill h3"></i>
                    </div>
                    <h6>1. Enter Details</h6>
                    <p class="small">Provide your name, email, and mobile number</p>
                </div>
                <div class="col-md-4 text-center mb-3">
                    <div class="bg-light rounded-circle p-3 mb-2 mx-auto" style="width: 70px; height: 70px;">
                        <i class="bi bi-shield-lock h3"></i>
                    </div>
                    <h6>2. Create Password</h6>
                    <p class="small">Set a secure password for your account</p>
                </div>
                <div class="col-md-4 text-center mb-3">
                    <div class="bg-light rounded-circle p-3 mb-2 mx-auto" style="width: 70px; height: 70px;">
                        <i class="bi bi-check-circle h3"></i>
                    </div>
                    <h6>3. Confirm & Start</h6>
                    <p class="small">Verify your email and start creating</p>
                </div>
            </div>
            ''',
            'tips': [
                {
                    'title': 'Use a Professional Email',
                    'content': 'Use your work or organization email for better credibility.'
                },
                {
                    'title': 'Strong Password',
                    'content': 'Create a strong password with letters, numbers, and symbols.'
                },
                {
                    'title': 'Verify Email',
                    'content': 'Check your inbox to verify your email address immediately.'
                },
                {
                    'title': 'Bookmark Login',
                    'content': 'Bookmark the login page for quick access.'
                }
            ],
            'next_step': 'Once your account is created, you can start building your first event registration form.',
            'action_url': '/signup',
            'action_text': 'Sign Up Now',
            'video_caption': 'Video tutorial coming soon - showing account creation process',
        },
        2: {
            'title': 'Create Event & Form',
            'subtitle': 'Build your perfect registration form',
            'description': 'Set up your event details and create a customized registration form that matches your needs.',
            'icon': '<i class="bi bi-pencil-square"></i>',
            'content': '''
            <h5 class="mb-3">Event Creation Process</h5>
            
            <div class="row mb-4">
                <div class="col-md-6">
                    <div class="card bg-light border-0 h-100">
                        <div class="card-body">
                            <h6><i class="bi bi-calendar-plus text-primary me-2"></i>Step 1: Create Event</h6>
                            <p class="small mb-0">Start by creating a new event with basic details:</p>
                            <ul class="small mt-2">
                                <li>Event name and description</li>
                                <li>Date and time information</li>
                                <li>Location details (optional)</li>
                                <li>Organizer information</li>
                            </ul>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card bg-light border-0 h-100">
                        <div class="card-body">
                            <h6><i class="bi bi-card-checklist text-primary me-2"></i>Step 2: Build Form</h6>
                            <p class="small mb-0">Create your registration form with our intuitive builder:</p>
                            <ul class="small mt-2">
                                <li>Add various question types</li>
                                <li>Set required/optional fields</li>
                                <li>Configure file upload options</li>
                                <li>Preview before publishing</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            
            <h5 class="mb-3">Available Question Types</h5>
            <div class="row">
                <div class="col-md-3 col-6 text-center mb-3">
                    <span class="badge bg-primary w-100 py-2">Text Input</span>
                </div>
                <div class="col-md-3 col-6 text-center mb-3">
                    <span class="badge bg-primary w-100 py-2">Email</span>
                </div>
                <div class="col-md-3 col-6 text-center mb-3">
                    <span class="badge bg-primary w-100 py-2">Phone</span>
                </div>
                <div class="col-md-3 col-6 text-center mb-3">
                    <span class="badge bg-success w-100 py-2">Multiple Choice</span>
                </div>
                <div class="col-md-3 col-6 text-center mb-3">
                    <span class="badge bg-success w-100 py-2">Checkboxes</span>
                </div>
                <div class="col-md-3 col-6 text-center mb-3">
                    <span class="badge bg-success w-100 py-2">Dropdown</span>
                </div>
                <div class="col-md-3 col-6 text-center mb-3">
                    <span class="badge bg-warning w-100 py-2">File Upload</span>
                </div>
                <div class="col-md-3 col-6 text-center mb-3">
                    <span class="badge bg-warning w-100 py-2">Date Picker</span>
                </div>
            </div>
            ''',
            'tips': [
                {
                    'title': 'Clear Event Description',
                    'content': 'Write a clear description to help participants understand the event.'
                },
                {
                    'title': 'Essential Questions Only',
                    'content': 'Ask only essential questions to maximize completion rates.'
                },
                {
                    'title': 'Mobile Optimization',
                    'content': 'Test your form on mobile devices to ensure good user experience.'
                },
                {
                    'title': 'Save Progress',
                    'content': 'You can save drafts and come back later to finish.'
                }
            ],
            'next_step': 'After creating your form, it\'s time to share it with your audience.',
            'action_url': '/create_event',
            'action_text': 'Create Event',
            'video_caption': 'Video tutorial coming soon - showing form creation process',
        },
        3: {
            'title': 'Share & Collect Responses',
            'subtitle': 'Distribute your form and gather registrations',
            'description': 'Share your registration form through multiple channels and start collecting responses instantly.',
            'icon': '<i class="bi bi-share-fill"></i>',
            'content': '''
            <h5 class="mb-3">Multiple Sharing Options</h5>
            
            <div class="row mb-4">
                <div class="col-md-6 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <div class="d-flex">
                                <div class="flex-shrink-0">
                                    <i class="bi bi-envelope-fill text-primary h2"></i>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6>Email Invitations</h6>
                                    <p class="small mb-0">Send personalized email invites directly from EventFlow. Track opens and clicks.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <div class="d-flex">
                                <div class="flex-shrink-0">
                                    <i class="bi bi-qr-code-scan text-primary h2"></i>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6>QR Codes</h6>
                                    <p class="small mb-0">Generate QR codes for print materials, posters, and event badges.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <div class="d-flex">
                                <div class="flex-shrink-0">
                                    <i class="bi bi-link-45deg text-primary h2"></i>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6>Direct Links</h6>
                                    <p class="small mb-0">Copy and share unique form URLs on websites, social media, or messaging apps.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <div class="d-flex">
                                <div class="flex-shrink-0">
                                    <i class="bi bi-code-slash text-primary h2"></i>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6>Embed Codes</h6>
                                    <p class="small mb-0">Embed forms directly on your website with a simple code snippet.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <h5 class="mb-3">Response Collection Features</h5>
            <div class="row">
                <div class="col-md-4 text-center mb-3">
                    <div class="bg-light rounded-circle p-3 mb-2 mx-auto" style="width: 70px; height: 70px;">
                        <i class="bi bi-clock-history text-success h3"></i>
                    </div>
                    <h6>Real-time Updates</h6>
                    <p class="small">See responses as they come in</p>
                </div>
                <div class="col-md-4 text-center mb-3">
                    <div class="bg-light rounded-circle p-3 mb-2 mx-auto" style="width: 70px; height: 70px;">
                        <i class="bi bi-bell text-warning h3"></i>
                    </div>
                    <h6>Notifications</h6>
                    <p class="small">Get alerts for new responses</p>
                </div>
                <div class="col-md-4 text-center mb-3">
                    <div class="bg-light rounded-circle p-3 mb-2 mx-auto" style="width: 70px; height: 70px;">
                        <i class="bi bi-cloud-arrow-up text-info h3"></i>
                    </div>
                    <h6>Auto-save</h6>
                    <p class="small">Responses saved automatically</p>
                </div>
            </div>
            ''',
            'tips': [
                {
                    'title': 'Multiple Channels',
                    'content': 'Share through multiple channels to reach more people.'
                },
                {
                    'title': 'Personalize Emails',
                    'content': 'Add personal messages to increase engagement.'
                },
                {
                    'title': 'QR for Events',
                    'content': 'Use QR codes for on-site registration at events.'
                },
                {
                    'title': 'Schedule Emails',
                    'content': 'Send reminder emails as the event date approaches.'
                }
            ],
            'next_step': 'Monitor your responses and analyze the data with our powerful dashboard.',
            'action_url': '/dashboard',
            'action_text': 'View Dashboard',
            'video_caption': 'Video tutorial coming soon - showing form sharing and response collection',
        },
        4: {
            'title': 'Manage & Analyze Data',
            'subtitle': 'Export, analyze, and take action on your data',
            'description': 'Use our powerful analytics tools to understand your audience and export data for further analysis.',
            'icon': '<i class="bi bi-bar-chart-fill"></i>',
            'content': '''
            <h5 class="mb-3">Data Management Tools</h5>
            
            <div class="row mb-4">
                <div class="col-md-4 text-center mb-3">
                    <div class="card bg-light border-0 h-100">
                        <div class="card-body">
                            <i class="bi bi-eye-fill text-primary display-6 mb-3"></i>
                            <h6>Real-time Dashboard</h6>
                            <p class="small mb-0">Monitor registrations as they come in with our live dashboard.</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 text-center mb-3">
                    <div class="card bg-light border-0 h-100">
                        <div class="card-body">
                            <i class="bi bi-file-earmark-text-fill text-success display-6 mb-3"></i>
                            <h6>Export Options</h6>
                            <p class="small mb-0">Download data in CSV, PDF, or Excel formats for offline analysis.</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 text-center mb-3">
                    <div class="card bg-light border-0 h-100">
                        <div class="card-body">
                            <i class="bi bi-funnel-fill text-warning display-6 mb-3"></i>
                            <h6>Advanced Filters</h6>
                            <p class="small mb-0">Filter responses by date, question answer, or custom criteria.</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <h5 class="mb-3">Analytics & Insights</h5>
            <div class="row">
                <div class="col-md-6">
                    <ul class="list-check">
                        <li>Response rate tracking</li>
                        <li>Completion time analysis</li>
                        <li>Popular time slots</li>
                        <li>Device breakdown (mobile/desktop)</li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <ul class="list-check">
                        <li>Geographic distribution</li>
                        <li>Email open/click rates</li>
                        <li>Form abandonment analysis</li>
                        <li>Trend analysis over time</li>
                    </ul>
                </div>
            </div>
            
            <div class="alert alert-success mt-4">
                <h6><i class="bi bi-check-circle me-2"></i>Data Security</h6>
                <p class="mb-0 small">All your data is encrypted and securely stored. You maintain full ownership of all collected information.</p>
            </div>
            ''',
            'tips': [
                {
                    'title': 'Regular Exports',
                    'content': 'Export data regularly for backup and offline analysis.'
                },
                {
                    'title': 'Use Filters',
                    'content': 'Use filters to analyze specific segments of your audience.'
                },
                {
                    'title': 'Compare Events',
                    'content': 'Compare data across multiple events to identify trends.'
                },
                {
                    'title': 'Data Privacy',
                    'content': 'Always follow data privacy regulations when handling participant information.'
                }
            ],
            'next_step': 'Congratulations! You\'ve completed the EventFlow guide. Start creating your first event today!',
            'action_url': '/signup',
            'action_text': 'Get Started Free',
            'video_caption': 'Video tutorial coming soon - showing data analysis and export features',
        }
    }
    
    # Get the specific step data
    step_data = steps.get(step, {})
    
    # Merge with base template
    result = {**base_step, **step_data}
    
    return result

def get_all_step_data():
    """Get data for all steps"""
    return {step: get_step_data(step) for step in range(1, 5)}

def update_step_video(step, video_data):
    """Update video information for a specific step"""
    steps = get_all_step_data()
    
    if step in steps:
        steps[step].update(video_data)
        return True
    return False

def get_step_summary(step):
    """Get a brief summary of each step"""
    summaries = {
        1: {
            'title': 'Create Account',
            'description': 'Sign up for your free EventFlow account',
            'icon': 'bi-person-plus',
            'estimated_time': '1 minute'
        },
        2: {
            'title': 'Create Event & Form',
            'description': 'Build your custom registration form',
            'icon': 'bi-pencil-square',
            'estimated_time': '2-3 minutes'
        },
        3: {
            'title': 'Share & Collect',
            'description': 'Distribute your form and gather responses',
            'icon': 'bi-share',
            'estimated_time': '1-2 minutes'
        },
        4: {
            'title': 'Manage Data',
            'description': 'Analyze responses and export data',
            'icon': 'bi-bar-chart',
            'estimated_time': '1 minute'
        }
    }
    return summaries.get(step, {})

def get_video_status(step):
    """Get video availability status for a step"""
    step_data = get_step_data(step)
    
    if step_data.get('video_type') == 'file' and step_data.get('video_file'):
        return {
            'available': True,
            'type': 'file',
            'duration': step_data.get('video_duration', 'Unknown'),
            'status': 'ready'
        }
    elif step_data.get('video_type') == 'embed' and step_data.get('video_url'):
        return {
            'available': True,
            'type': 'embed',
            'status': 'ready'
        }
    else:
        return {
            'available': False,
            'status': 'upcoming',
            'message': 'Video tutorial coming soon'
        }

# Helper function to generate URLs
def get_step_url(step, base_url=''):
    """Generate URL for a specific step"""
    return f"{base_url}/how-it-works/step/{step}"

def get_step_navigation(step):
    """Get previous and next step navigation"""
    prev_step = step - 1 if step > 1 else None
    next_step = step + 1 if step < 4 else None
    
    return {
        'current': step,
        'prev': prev_step,
        'next': next_step,
        'total': 4
    }

if __name__ == '__main__':
    # Test the module
    print("Testing How It Works Data Module")
    print("=" * 50)
    
    for step in range(1, 5):
        data = get_step_data(step)
        print(f"\nStep {step}: {data['title']}")
        print(f"Video Status: {get_video_status(step)}")
        print(f"Tips: {len(data.get('tips', []))}")
    
    print("\n" + "=" * 50)
    print(f"Total steps loaded: 4")
