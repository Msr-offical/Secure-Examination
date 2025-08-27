/**
 * CYGENTIC AI Test Center - Futuristic Animation System
 * Advanced 3D animations, particle effects, and interactive elements
 */

class FuturisticAnimations {
    constructor() {
        this.particles = [];
        this.neuralNodes = [];
        this.isReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        this.animationFrameId = null;
        this.lastTime = 0;
        
        this.init();
    }

    init() {
        this.createFuturisticBackground();
        this.setupScrollAnimations();
        this.initParticleSystem();
        this.createNeuralNetwork();
        this.setupInteractiveElements();
        this.startAnimationLoop();
        
        // Reduced motion support
        if (this.isReducedMotion) {
            this.disableAnimations();
        }
    }

    /**
     * Create the futuristic animated background
     */
    createFuturisticBackground() {
        const body = document.body;
        
        // Create main background container
        const bgContainer = document.createElement('div');
        bgContainer.className = 'futuristic-bg';
        bgContainer.innerHTML = `
            <div class="digital-grid"></div>
            <div class="neural-network"></div>
            <div class="floating-shapes"></div>
        `;
        
        body.insertBefore(bgContainer, body.firstChild);
        
        this.bgContainer = bgContainer;
        this.createFloatingShapes();
    }

    /**
     * Create floating geometric shapes
     */
    createFloatingShapes() {
        const shapesContainer = this.bgContainer.querySelector('.floating-shapes');
        const shapeCount = window.innerWidth < 768 ? 8 : 15;
        
        for (let i = 0; i < shapeCount; i++) {
            const shape = document.createElement('div');
            shape.className = 'hex-shape';
            shape.style.left = Math.random() * 100 + '%';
            shape.style.top = Math.random() * 100 + '%';
            shape.style.animationDelay = Math.random() * 8 + 's';
            shape.style.animationDuration = (8 + Math.random() * 4) + 's';
            
            shapesContainer.appendChild(shape);
        }
    }

    /**
     * Initialize particle system
     */
    initParticleSystem() {
        const particleCount = window.innerWidth < 768 ? 20 : 40;
        
        for (let i = 0; i < particleCount; i++) {
            this.createParticle();
        }
    }

    /**
     * Create individual particle
     */
    createParticle() {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + 'vw';
        particle.style.animationDelay = Math.random() * 15 + 's';
        particle.style.animationDuration = (15 + Math.random() * 10) + 's';
        
        this.bgContainer.appendChild(particle);
        
        // Remove and recreate particle after animation
        particle.addEventListener('animationend', () => {
            particle.remove();
            this.createParticle();
        });
    }

    /**
     * Create neural network nodes and connections
     */
    createNeuralNetwork() {
        const networkContainer = this.bgContainer.querySelector('.neural-network');
        const nodeCount = window.innerWidth < 768 ? 12 : 20;
        
        // Create nodes
        for (let i = 0; i < nodeCount; i++) {
            const node = document.createElement('div');
            node.className = 'neural-node';
            
            const x = Math.random() * 100;
            const y = Math.random() * 100;
            
            node.style.left = x + '%';
            node.style.top = y + '%';
            node.style.animationDelay = Math.random() * 3 + 's';
            
            networkContainer.appendChild(node);
            this.neuralNodes.push({ element: node, x, y });
        }
        
        // Create connections between nearby nodes
        this.createNeuralConnections(networkContainer);
    }

    /**
     * Create connections between neural nodes
     */
    createNeuralConnections(container) {
        this.neuralNodes.forEach((node, index) => {
            this.neuralNodes.slice(index + 1).forEach(otherNode => {
                const distance = Math.sqrt(
                    Math.pow(node.x - otherNode.x, 2) + 
                    Math.pow(node.y - otherNode.y, 2)
                );
                
                if (distance < 30) {
                    const connection = document.createElement('div');
                    connection.className = 'neural-connection';
                    
                    const angle = Math.atan2(otherNode.y - node.y, otherNode.x - node.x);
                    const length = distance + '%';
                    
                    connection.style.left = node.x + '%';
                    connection.style.top = node.y + '%';
                    connection.style.width = length;
                    connection.style.transform = `rotate(${angle}rad)`;
                    connection.style.animationDelay = Math.random() * 4 + 's';
                    
                    container.appendChild(connection);
                }
            });
        });
    }

    /**
     * Setup scroll-triggered animations
     */
    setupScrollAnimations() {
        const observerOptions = {
            root: null,
            rootMargin: '-10% 0px -10% 0px',
            threshold: 0.1
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    // Add staggered delays for elements in the same container
                    const container = entry.target.closest('.hero-cta, .grid');
                    if (container) {
                        const siblings = container.querySelectorAll('.fade-in-element');
                        siblings.forEach((sibling, index) => {
                            setTimeout(() => {
                                sibling.classList.add('in-view');
                            }, index * 200); // 200ms delay between each element
                        });
                    } else {
                        entry.target.classList.add('in-view');
                    }
                }
            });
        }, observerOptions);

        // Observe elements for scroll animations
        const animatedElements = document.querySelectorAll(
            '.fade-in-element, .portal-card, .hero-cta'
        );
        
        animatedElements.forEach((el, index) => {
            observer.observe(el);
        });
    }

    /**
     * Trigger animation for specific element
     */
    triggerElementAnimation(element) {
        if (element.classList.contains('portal-card')) {
            element.classList.add('animate-slide-up');
        } else if (element.classList.contains('hero-cta')) {
            element.classList.add('animate-slide-up');
        }
    }

    /**
     * Setup interactive elements
     */
    setupInteractiveElements() {
        // Enhanced button hover effects
        const buttons = document.querySelectorAll('.btn-primary, .btn-secondary');
        buttons.forEach(button => {
            button.addEventListener('mouseenter', this.onButtonHover.bind(this));
            button.addEventListener('mouseleave', this.onButtonLeave.bind(this));
        });

        // Portal card magnetic effect
        const portalCards = document.querySelectorAll('.portal-card');
        portalCards.forEach(card => {
            card.addEventListener('mouseenter', this.onCardMouseMove.bind(this));
            card.addEventListener('mouseleave', this.onCardMouseLeave.bind(this));
        });

        // Icon bounce effects
        const icons = document.querySelectorAll('svg');
        icons.forEach(icon => {
            icon.classList.add('icon-bounce');
        });

        // Removed tooltip functionality
        // this.setupTooltips();
    }

    /**
     * Button hover effect
     */
    onButtonHover(event) {
        const button = event.target;
        button.style.transform = 'translateY(-4px)';
        
        // Create ripple effect
        this.createRippleEffect(button, event);
    }

    /**
     * Button leave effect
     */
    onButtonLeave(event) {
        const button = event.target;
        button.style.transform = '';
    }

    /**
     * Clean card hover effect - removed rotation for professional look
     */
    onCardMouseMove(event) {
        const card = event.currentTarget;
        
        // Apply clean hover effect without rotation
        const cardType = card.classList.contains('student-portal') ? 'cyan' : 
                       card.classList.contains('examiner-portal') ? 'blue' : 'amber';
                       
        let shadowColor = 'rgba(6, 182, 212, 0.25)';
        if (cardType === 'blue') shadowColor = 'rgba(59, 130, 246, 0.25)';
        if (cardType === 'amber') shadowColor = 'rgba(245, 158, 11, 0.25)';
        
        card.style.transform = 'translateY(-4px)';
        card.style.boxShadow = `0 8px 25px ${shadowColor}, 0 0 20px ${shadowColor.replace('0.25', '0.1')}`;
        card.style.transition = 'all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1)';
    }

    /**
     * Card mouse leave effect
     */
    onCardMouseLeave(event) {
        const card = event.currentTarget;
        card.style.transform = '';
    }

    /**
     * Create ripple effect on button click
     */
    createRippleEffect(element, event) {
        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;
        
        const ripple = document.createElement('div');
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: radial-gradient(circle, rgba(6, 182, 212, 0.6) 0%, transparent 70%);
            border-radius: 50%;
            transform: scale(0);
            animation: ripple 0.6s ease-out forwards;
            pointer-events: none;
            z-index: 0;
        `;
        
        element.style.position = 'relative';
        element.style.overflow = 'hidden';
        element.appendChild(ripple);
        
        setTimeout(() => ripple.remove(), 600);
    }

    /**
     * Setup tooltip functionality - Removed for cleaner design as specified
     */
    setupTooltips() {
        // Tooltip functionality removed for cleaner design per specifications
    }

    /**
     * Animation loop for continuous effects
     */
    startAnimationLoop() {
        const animate = (currentTime) => {
            if (currentTime - this.lastTime >= 16) { // ~60fps
                this.updateAnimations();
                this.lastTime = currentTime;
            }
            
            this.animationFrameId = requestAnimationFrame(animate);
        };
        
        this.animationFrameId = requestAnimationFrame(animate);
    }

    /**
     * Update continuous animations
     */
    updateAnimations() {
        // Add any continuous animations here
        // For now, CSS handles most animations for better performance
    }

    /**
     * Disable animations for reduced motion users
     */
    disableAnimations() {
        const style = document.createElement('style');
        style.textContent = `
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        `;
        document.head.appendChild(style);
    }

    /**
     * Cleanup method
     */
    destroy() {
        if (this.animationFrameId) {
            cancelAnimationFrame(this.animationFrameId);
        }
        
        if (this.bgContainer) {
            this.bgContainer.remove();
        }
    }

    /**
     * Resize handler
     */
    handleResize() {
        // Recreate elements based on new screen size
        const shapesContainer = this.bgContainer.querySelector('.floating-shapes');
        shapesContainer.innerHTML = '';
        this.createFloatingShapes();
        
        const networkContainer = this.bgContainer.querySelector('.neural-network');
        networkContainer.innerHTML = '';
        this.neuralNodes = [];
        this.createNeuralNetwork();
    }
}

// CSS for ripple animation
const rippleCSS = `
@keyframes ripple {
    to {
        transform: scale(2);
        opacity: 0;
    }
}
`;

// Add ripple CSS to document
const rippleStyle = document.createElement('style');
rippleStyle.textContent = rippleCSS;
document.head.appendChild(rippleStyle);

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const futuristicAnimations = new FuturisticAnimations();
    
    // Handle window resize
    let resizeTimeout;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
            futuristicAnimations.handleResize();
        }, 250);
    });
    
    // Expose to global scope for debugging
    window.futuristicAnimations = futuristicAnimations;
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FuturisticAnimations;
}