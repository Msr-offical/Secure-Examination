# Dashboard UI Scaffolding - Development Guide

## Overview
This document outlines the structural wireframes, UI scaffolding, and implementation details for the CYGENTIC AI Test Center dashboard system. The implementation includes three key user dashboards with consistent design patterns and reusable components.

## Routing Paths and URL Structure

### Student Portal Routes
- `/student/dashboard` - Student Dashboard (main overview)
- `/student/tests` - Available Tests module
- `/student/results` - Results & Analytics module
- `/student/profile` - Profile Settings module
- `/student/proctoring-check` - Proctoring readiness check

### Examiner Portal Routes
- `/examiner/dashboard` - Examiner Dashboard (main overview)
- `/examiner/monitoring` - Live proctoring monitor
- `/examiner/questions` - Question bank management
- `/examiner/schedule` - Test scheduling module
- `/examiner/students` - Student management
- `/examiner/results` - Results management

### Admin Portal Routes
- `/admin/dashboard` - Admin Dashboard (main overview)
- `/admin/users` - User management (students & examiners)
- `/admin/examiners` - Examiner management
- `/admin/analytics` - Analytics & reports
- `/admin/system` - Master settings
- `/admin/notifications` - Platform notifications
- `/admin/security` - Security center

## File Structure and Naming Conventions

### Template Organization
```
templates/
├── dashboards/
│   ├── student_dashboard.html      # Main student dashboard
│   ├── student_tests.html          # Available tests
│   ├── student_results.html        # Results & analytics
│   ├── student_profile.html        # Profile settings
│   ├── examiner_dashboard.html     # Main examiner dashboard
│   ├── examiner_monitoring.html    # Live monitoring
│   ├── examiner_questions.html     # Question bank
│   ├── examiner_schedule.html      # Test scheduling
│   ├── admin_dashboard.html        # Main admin dashboard
│   ├── admin_users.html            # User management
│   ├── admin_analytics.html        # Analytics
│   └── admin_system.html           # System settings
└── base.html                       # Base template with common layout
```

### CSS Class Naming Conventions

#### Layout Classes
- `.dashboard-layout` - Main dashboard container
- `.dashboard-sidebar` - Fixed sidebar navigation
- `.dashboard-main` - Main content area
- `.dashboard-topbar` - Top navigation bar
- `.mobile-open` - Mobile sidebar visibility state

#### Component Classes
- `.card` - Base card container
- `.card-header` - Card header section
- `.card-body` - Card content area
- `.card-footer` - Card footer section
- `.status-card` - Dashboard status/metric cards
- `.status-card-icon` - Status card icon container
- `.status-card-value` - Status card main value
- `.status-card-label` - Status card label text

#### Navigation Classes
- `.sidebar-nav` - Sidebar navigation container
- `.sidebar-link` - Individual sidebar navigation link
- `.sidebar-link.active` - Active/current page link
- `.topbar-title` - Main page title
- `.topbar-subtitle` - Page description
- `.topbar-actions` - Top bar action buttons

#### Button Classes
- `.btn` - Base button class
- `.btn-primary` - Primary action button (cyan/blue gradient)
- `.btn-secondary` - Secondary action button (slate background)
- `.btn-success` - Success button (green gradient)
- `.btn-warning` - Warning button (yellow/orange gradient)
- `.btn-danger` - Danger button (red/pink gradient)
- `.btn-ghost` - Transparent button with border
- `.btn-sm` - Small button size
- `.btn-lg` - Large button size

#### Badge Classes
- `.badge` - Base badge component
- `.badge-primary` - Primary badge (cyan)
- `.badge-secondary` - Secondary badge (slate)
- `.badge-success` - Success badge (green)
- `.badge-warning` - Warning badge (yellow)
- `.badge-danger` - Danger badge (red)

#### Status Indicator Classes
- `.status-indicator` - Base status dot
- `.status-online` - Online status (green)
- `.status-offline` - Offline status (gray)
- `.status-busy` - Busy status (yellow)
- `.status-away` - Away status (orange)

#### Form Classes
- `.form-group` - Form field container
- `.form-label` - Form field label
- `.form-input` - Base input styling
- `.form-textarea` - Textarea styling
- `.form-select` - Select dropdown styling
- `.form-checkbox` - Checkbox styling
- `.form-radio` - Radio button styling

#### Table Classes
- `.table-container` - Table wrapper with card styling
- `.table` - Base table class
- `.table-header` - Table header section
- `.table-row` - Table row styling
- `.table-cell` - Table cell styling

#### Modal Classes
- `.modal-overlay` - Modal backdrop
- `.modal` - Modal container
- `.modal-header` - Modal header
- `.modal-title` - Modal title
- `.modal-close` - Modal close button
- `.modal-body` - Modal content
- `.modal-footer` - Modal footer with actions

#### Alert Classes
- `.alert` - Base alert component
- `.alert-info` - Info alert (cyan)
- `.alert-success` - Success alert (green)
- `.alert-warning` - Warning alert (yellow)
- `.alert-danger` - Danger alert (red)

#### Progress Classes
- `.progress` - Progress bar container
- `.progress-bar` - Progress bar fill
- `.progress-primary` - Primary progress (cyan/blue)
- `.progress-success` - Success progress (green)
- `.progress-warning` - Warning progress (yellow)
- `.progress-danger` - Danger progress (red)

#### Animation Classes
- `.animate-glow` - Glowing animation effect
- `.animate-pulse-soft` - Soft pulsing animation
- `.gpu-accelerated` - Hardware acceleration optimization

## Color Palette and Design System

### Primary Colors
- **Cyan**: `#06b6d4` (Primary brand color)
- **Blue**: `#3b82f6` (Secondary brand color)
- **Purple**: `#8b5cf6` (Accent color)
- **Yellow**: `#f59e0b` (Warning/admin color)

### Status Colors
- **Success**: `#10b981` (Green)
- **Warning**: `#f59e0b` (Yellow/Orange)
- **Danger**: `#ef4444` (Red)
- **Info**: `#06b6d4` (Cyan)

### Background Colors
- **Primary Background**: `from-slate-900 via-blue-900 to-slate-800`
- **Card Background**: `slate-800/30 with backdrop-blur`
- **Sidebar Background**: `slate-900/95 with backdrop-blur`

### Border Colors
- **Primary Border**: `cyan-500/20`
- **Secondary Border**: `slate-700/50`
- **Warning Border**: `yellow-500/20`

## Typography System

### Font Families
- **Primary**: 'Poppins' (body text, UI elements)
- **Headings**: 'Montserrat' (titles, headers)

### Font Sizes and Weights
- **Hero Title**: `text-4xl sm:text-5xl lg:text-7xl font-bold`
- **Page Title**: `text-3xl font-bold` (topbar-title)
- **Section Header**: `text-xl font-bold`
- **Card Title**: `text-lg font-semibold`
- **Body Text**: `text-base`
- **Small Text**: `text-sm`
- **Caption**: `text-xs`

## Responsive Design Breakpoints

### Screen Sizes
- **Mobile**: `< 768px` (sidebar hidden, mobile menu)
- **Tablet**: `768px - 1023px` (adjusted padding, responsive grids)
- **Desktop**: `1024px+` (full sidebar, optimal layout)

### Responsive Utilities
- **Grid Responsive**: `grid-cols-1 md:grid-cols-2 lg:grid-cols-4`
- **Padding Responsive**: `p-4 md:p-6 lg:p-8`
- **Text Responsive**: `text-base md:text-lg lg:text-xl`

## Component Architecture

### Reusable UI Components

#### Dashboard Cards
```html
<div class="card">
    <div class="card-header">
        <h2 class="text-xl font-bold text-white">Card Title</h2>
    </div>
    <div class="card-body">
        <!-- Card content -->
    </div>
    <div class="card-footer">
        <!-- Card actions -->
    </div>
</div>
```

#### Status Cards
```html
<div class="status-card">
    <div class="status-card-icon bg-gradient-to-br from-cyan-500/20 to-blue-500/20">
        <!-- Icon SVG -->
    </div>
    <div class="status-card-value">123</div>
    <div class="status-card-label">Metric Label</div>
    <div class="text-xs text-cyan-400 mt-1">Additional info</div>
</div>
```

#### Sidebar Navigation
```html
<nav class="sidebar-nav">
    <a href="/route" class="sidebar-link active">
        <!-- Icon SVG -->
        <span>Label</span>
        <span class="badge badge-primary ml-auto">5</span>
    </a>
</nav>
```

#### Action Buttons
```html
<button class="btn btn-primary">
    <!-- Icon SVG -->
    Button Text
</button>
```

#### Progress Bars
```html
<div class="progress progress-primary">
    <div class="progress-bar" style="width: 75%"></div>
</div>
```

#### Badges and Status Indicators
```html
<span class="badge badge-success">Active</span>
<div class="status-online"></div>
```

## Dashboard Module Structure

### Student Dashboard Modules
1. **Test Schedule Module** - Upcoming and scheduled tests
2. **Ongoing Tests Module** - Currently active test sessions
3. **Results Module** - Performance analytics and scores
4. **Proctoring Readiness Module** - System compatibility checks

### Examiner Dashboard Modules
1. **Live Monitoring Module** - Real-time test session oversight
2. **Student Management Module** - Student profiles and activity
3. **Question Bank Module** - Question creation and management
4. **Test Scheduling Module** - Test session planning
5. **Results Management Module** - Grade review and analytics

### Admin Dashboard Modules
1. **System Health Monitor** - Server and service status
2. **User Management Module** - Student and examiner accounts
3. **Examiner Management Module** - Examiner permissions and oversight
4. **Analytics Module** - Platform-wide metrics and reports
5. **Master Settings Module** - System configuration
6. **Platform Notifications Module** - System alerts and announcements

## Implementation Guidelines

### Development Best Practices
1. **Consistent Naming**: Follow established CSS class conventions
2. **Component Reuse**: Utilize predefined UI components
3. **Responsive Design**: Test across all breakpoints
4. **Accessibility**: Include proper ARIA labels and semantic HTML
5. **Performance**: Use CSS animations sparingly and optimize for mobile

### Icon System
- Use **Heroicons** for consistent iconography
- Icon sizes: `w-4 h-4` (small), `w-5 h-5` (medium), `w-6 h-6` (large)
- Icon colors match component themes (cyan, blue, green, yellow, red)

### State Management
- **Active States**: `.active` class for current page/selection
- **Loading States**: Use `.animate-pulse` for loading indicators
- **Error States**: Use `.alert-danger` for error messages
- **Success States**: Use `.alert-success` for confirmations

## Mobile Optimization

### Mobile-Specific Features
1. **Collapsible Sidebar**: Hidden by default, toggle-able
2. **Touch-Friendly Buttons**: Adequate tap targets (44px minimum)
3. **Simplified Navigation**: Reduced menu items on mobile
4. **Responsive Cards**: Stack on mobile, grid on desktop
5. **Mobile Menu Toggle**: Hamburger menu for sidebar access

### Mobile CSS Classes
- `.mobile-open` - Show sidebar on mobile
- `.lg:hidden` - Hide on large screens
- `.md:grid-cols-2` - Responsive grid layouts
- `.sm:text-lg` - Responsive typography

This documentation provides the foundation for consistent development and maintenance of the dashboard system. All components are designed to be reusable, accessible, and responsive across different devices and user roles.