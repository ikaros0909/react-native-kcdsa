
Pod::Spec.new do |s|
  s.name          = 'react-native-kcdsa'
  s.version       = '0.9.6'
  s.summary       = 'KCDSA'
  s.author        = "nixstory@gmail.com"
  s.license       = 'MIT'
  s.requires_arc  = true
  s.homepage      = "https://github.com/reactspring/react-native-kcdsa"
  s.source        = { :git => 'https://github.com/reactspring/react-native-kcdsa' }
  s.platform      = :ios, '9.0'
  s.source_files  = "ios/**/*.{h,m}"

  s.dependency "React"
end
